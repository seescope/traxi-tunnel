#![feature(test)]
#![feature(lookup_host)]
#![cfg_attr(debug_assertions, deny(warnings))]
#![allow(unused_features)] // Rust gets mad about the test feature.
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

extern crate ansi_term;
extern crate bit_vec;
extern crate byteorder;
extern crate bytes;
extern crate chrono;
extern crate fnv;
extern crate httparse;
extern crate hyper;
extern crate hyper_native_tls;
extern crate itertools;
extern crate jni_sys;
extern crate libc;
extern crate mio;
extern crate net2;
extern crate nix;
extern crate pnet;
extern crate rand;
extern crate regex;
extern crate rusoto_core;
extern crate rusoto_credential;
extern crate rusoto_kinesis;
extern crate rustc_serialize;
extern crate ssl_interceptor;
extern crate time;

pub mod tunnel;
pub mod packet_helper;
mod http_decoder;
mod https_decoder;
pub mod app_logger;
mod firebase_connector;
pub mod tcp;
pub mod udp;
pub mod test_utils;
pub mod kinesis_handler;
pub mod log_entry;

use std::os::unix::io::AsRawFd;
use std::ffi::{CStr, CString};
use std::io;
use std::result;
use std::thread::{sleep, spawn};
use std::collections::HashMap;
use std::time::Duration;
use std::net::Ipv4Addr;
use mio::{EventSet, Io, PollOpt};
use libc::c_int;
use jni_sys::{jobject, jstring, JNIEnv, jmethodID};
use nix::fcntl::FcntlArg::F_SETFL;
use nix::fcntl::{fcntl, O_NONBLOCK};
use tunnel::{Environment, TraxiMessage, TraxiTunnel};
use firebase_connector::{Firebase, FirebaseConnector};
use rusoto_core::CredentialsError;

const TUNNEL: mio::Token = mio::Token(0);
const IPC: mio::Token = mio::Token(1);
#[cfg(all(target_os = "android", debug_assertions))]
fn init_logging() {
    use log::LogLevel;
    extern crate android_logger;
    let log_level = LogLevel::Debug;
    android_logger::init_once(log_level);
}

#[cfg(all(target_os = "android", not(debug_assertions)))]
fn init_logging() {
    use log::LogLevel;
    extern crate android_logger;
    let log_level = LogLevel::Info;
    android_logger::init_once(log_level);
}

#[cfg(not(target_os = "android"))]
fn init_logging() {
    extern crate log4rs;
    log4rs::init_file("/config/log4rs.yml", Default::default()).unwrap();
}


fn set_nonblock(s: &AsRawFd) {
    assert!(fcntl(s.as_raw_fd(), F_SETFL(O_NONBLOCK)).is_ok());
}

struct AndroidEnvironment {
    jre: *mut JNIEnv,
    thiz: jobject,
    package_id_map: HashMap<usize, String>,
    uuid: String,
    file_path: String,
}


#[derive(Debug)]
pub enum PacketError {
    RejectPacket(String),
    DropPacket(String),
}

#[derive(Debug)]
pub enum TraxiError {
    Io(io::Error),
    CredentialsError(CredentialsError),
    PacketError(PacketError),
    IPCError(String),
    TunnelError(String),
    HyperError(hyper::Error),
}

impl From<io::Error> for TraxiError {
    fn from(err: io::Error) -> TraxiError {
        TraxiError::Io(err)
    }
}

impl From<CredentialsError> for TraxiError {
    fn from(err: CredentialsError) -> TraxiError {
        TraxiError::CredentialsError(err)
    }
}

impl From<PacketError> for TraxiError {
    fn from(err: PacketError) -> TraxiError {
        TraxiError::PacketError(err)
    }
}

impl From<hyper::Error> for TraxiError {
    fn from(err: hyper::Error) -> TraxiError {
        TraxiError::HyperError(err)
    }
}

pub type Result<T> = result::Result<T, TraxiError>;

impl Environment for AndroidEnvironment {
    fn protect(&self, socket: c_int) -> bool {
        unsafe {
            let other_jre = **self.jre;
            let protect = get_method_id(self.jre, self.thiz, "protect", "(I)Z");

            // Call the method.
            let is_protected = (other_jre.CallBooleanMethod)(self.jre, self.thiz, protect, socket);

            is_protected == 1
        }
    }

    fn get_package_name(&mut self, package_id: usize) -> String {
        unsafe {
            self.package_id_map
                .entry(package_id)
                .or_insert({
                    let other_jre = **self.jre;
                    let package_id = package_id as c_int;
                    let method = get_method_id(
                        self.jre,
                        self.thiz,
                        "getApplicationName",
                        "(I)Ljava/lang/String;",
                    );

                    // Call the method.
                    let package_name_jstring =
                        (other_jre.CallObjectMethod)(self.jre, self.thiz, method, package_id)
                            as jstring;

                    let package_name = jstring_to_str(package_name_jstring, self.jre);

                    // JNI created objects aren't garbage collected, so kill the reference straight away.
                    (other_jre.DeleteLocalRef)(self.jre, package_name_jstring);

                    package_name
                })
                .clone()
        }
    }

    fn report_error(&self, message: &str) {
        // TODO: Improve
        error!("{}", message);
        report_error_to_firebase(self.jre, self.thiz, message);
    }

    fn get_uuid(&mut self, _: &Ipv4Addr) -> Option<String> {
        Some(self.uuid.clone())
    }

    fn get_file_path(&self) -> String {
        self.file_path.clone()
    }
}

fn report_error_to_firebase(env: *mut JNIEnv, thiz: jobject, message: &str) {
    unsafe {
        let other_jre = **env;
        let method = get_method_id(env, thiz, "reportError", "(Ljava/lang/String;)V");

        // Make sure we clone here. The JVM is a foul temptress - we dare not challenge her.
        let message = CString::new(message.clone()).unwrap().as_ptr();
        let message_jstring = (other_jre.NewStringUTF)(env, message);
        (other_jre.CallVoidMethod)(env, thiz, method, message_jstring);
    }
}

fn get_method_id(
    env: *mut JNIEnv,
    thiz: jobject,
    method_name: &str,
    method_signature: &str,
) -> jmethodID {
    unsafe {
        let other_jre = **env;

        // The method names and signatures must be of type *const c_char. This seems to do the
        // trick.
        let method_name = CString::new(method_name).unwrap();
        let method_name_ptr = method_name.as_ptr();
        let method_signature = CString::new(method_signature).unwrap();
        let method_signature_ptr = method_signature.as_ptr();

        // Get the corresponding class for "thiz".
        let class = (other_jre.GetObjectClass)(env, thiz);

        // Get the method ID
        let method_id = (other_jre.GetMethodID)(env, class, method_name_ptr, method_signature_ptr);

        // Clean up the class we created
        (other_jre.DeleteLocalRef)(env, class);

        // Return the method_id
        method_id
    }
}


fn jstring_to_str(jstring: jstring, jre: *mut JNIEnv) -> String {
    unsafe {
        debug!(
            "jstring_to_str| Attempting to convert jstring {:?}",
            jstring
        );
        let other_jre = **jre;
        let mut is_copy = 0u8;
        let chars = (other_jre.GetStringUTFChars)(jre, jstring, &mut is_copy);
        let cstring = CStr::from_ptr(chars);
        debug!("jstring_to_str| Got cstring {:?}", cstring);

        match cstring.to_str() {
            Ok(string) => {
                let result = string.to_string();
                debug!("jstring_to_str| Got String {:?}", result);
                (other_jre.ReleaseStringUTFChars)(jre, jstring, chars);
                result
            }
            Err(e) => {
                error!(
                    "jstring_to_str| Error converting {:?} to jstring: {:?}",
                    cstring, e
                );
                panic!();
            }
        }
    }
}

#[allow(unused_must_use)]
fn report_installed(uuid: String) {
    spawn(move || {
        // Wait a second.
        sleep(Duration::from_secs(1));

        // Build up the firebase connector.
        let base_url = format!("https://traxiapp.firebaseIO.com/kids/{}", uuid);
        let firebase_connector = Firebase::new(base_url);

        firebase_connector
            .report_installed()
            .map_err(|e| error!("{:?}", e));
    });
}


#[allow(unused_must_use)]
fn start_tunnel(
    environment: AndroidEnvironment,
    fd: c_int,
    uuid: String,
    file_path: String,
) -> Result<()> {
    // Build the tunnel.
    info!("START_TUNNEL| Building tunnel from fd: {}", fd);
    let tunnel = Io::from_raw_fd(fd);
    set_nonblock(&tunnel);

    // Get the IPC file ready.
    let ipc_path = format!("{}/ipc", &file_path);
    info!(
        "START_TUNNEL| Removing existing ipc file at: {:?}",
        ipc_path
    );
    std::fs::remove_file(&ipc_path);

    // Build the IPC server.
    info!("START_TUNNEL| Starting IPC server at: {:?}", ipc_path);
    let ipc_server = try!(mio::unix::UnixListener::bind(&ipc_path));

    // Create an event loop.
    info!("START_TUNNEL| Starting event loop");
    let mut event_loop = try!(mio::EventLoop::new());

    // Register the tunnel.
    info!("START_TUNNEL| Registering tunnel");
    try!(event_loop.register(&tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()));

    // Register the IPC server.
    info!("START_TUNNEL| Registering IPC server");

    try!(event_loop.register(&ipc_server, IPC, EventSet::readable(), PollOpt::edge()));

    // Start the SSL Intercept server.
    info!("START_TUNNEL| Starting SSL Intercept server wrapper thread");
    spawn(move || {
        info!("START_TUNNEL| Starting SSL child!");
        let child = spawn(move || {
            info!("START_TUNNEL| Inside SSL child thread, starting server for real.");
            info!("START_TUNNEL| Inside SSL child thread, starting server for real.");
            match ssl_interceptor::start_server() {
                Ok(_) => error!("SSL Server exited for some reason!"),
                Err(e) => error!("Error in SSL server thread: {:?}", e),
            };
        });

        info!("START_TUNNEL| Joining SSL child thread..");
        match child.join() {
            Ok(_) => error!("|JOIN_HANDLE| SSL Server exited for some reason!"),
            Err(e) => error!("|JOIN_HANDLE| Error in SSL server thread: {:?}", e),
        }
    });

    // Report the app as installed.
    info!("START_TUNNEL| Starting report_installed thread.");
    report_installed(uuid.clone());

    let mut handler = TraxiTunnel::new(tunnel, environment, ipc_server);

    // Set the timer for flush_log.
    let flush_log_timeout = Duration::from_millis(1000); // 1 second
    drop(event_loop.timeout(TraxiMessage::FlushLogQueue, flush_log_timeout)); // Drop, since timeout should never fail.
    info!("START_TUNNEL| Set FlushLogQueue timer to 1 second.");

    info!("START_TUNNEL| Setup complete. Starting event loop.");
    event_loop
        .run(&mut handler)
        .map_err(|e| TraxiError::from(e))
}

/// Start the Traxi VPN service.
#[no_mangle]
pub extern "C" fn Java_com_traxichildapp_TraxiVPNService_start(
    jre: *mut JNIEnv,
    thiz: jobject,
    fd: c_int,
    path: jstring,
    uuid: jstring,
) -> c_int {
    init_logging();

    // Set up logging.
    let file_path = jstring_to_str(path, jre);
    let uuid = jstring_to_str(uuid, jre);

    // Build the environment with pointers into the JVM.
    let environment = AndroidEnvironment {
        jre: jre,
        thiz: thiz,
        package_id_map: HashMap::new(),
        uuid: uuid.clone(),
        file_path: file_path.clone(),
    };

    match start_tunnel(environment, fd, uuid, file_path) {
        Ok(()) => fd,
        Err(e) => {
            let message = format!("START_VPN| Error starting VPN: {:?}", e);
            report_error_to_firebase(jre, thiz, &message);
            -1
        }
    }
}
