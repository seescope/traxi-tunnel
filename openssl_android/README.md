What's going on here?
====

Unfortunately, building Rust applications for Android that require OpenSSL is a bit of a pain. To work around this, we've got to build OpenSSL ourselves, then link against it.

How do I build OpenSSL?
===
You really shouldn't have to, as the arm binaries have been checked into GitHub, but if you're feeling particularly masochistic, run "make -f openssl.makefile" to download OpenSSL, extract it and build the appropriate binaries.
