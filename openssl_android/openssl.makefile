.PHONY: all
all: openssl
	@:  # No-op to silence the "make: Nothing to be done for 'all'." message.

# From http://wiki.openssl.org/index.php/Android
.PHONY: openssl
openssl: openssl-1.0.1t/libssl.so

openssl-1.0.1t/libssl.so: openssl-1.0.1t/Configure
	./openssl.sh ${ANDROID_NDK}

openssl-1.0.1t/Configure:
	echo "Configuring..
