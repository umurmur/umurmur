uMurmur - minimalistic Mumble server
====================================
Hosted on [GitHub](https://github.com/fatbob313/umurmur)

uMurmur is a minimalistic Mumble server primarily targeted to run on routers with an open OS like OpenWRT. The server part of Mumble is called Murmur, hence the name uMurmur. It is available as a precompiled package for some distributions. Check your package repository if you are running OpenWRT or Freetz.

There are makefiles in the [openwrt](https://github.com/fatbob313/umurmur/tree/master/openwrt) subdirectory suitable for building with the OpenWRT SDK. Move the Makefile of choice to the base directory, e.g.:

	mv openwrt/Makefile.polarssl Makefile

and then put the whole umurmur-X.X.X directory in the SDK's 'packages' directory.


Instructions for building from source
-------------------------------------
1. Requirements
	* [OpenSSL](http://www.openssl.org/) or [PolarSSL](http://polarssl.org/) library
	* [libconfig](http://www.hyperrealm.com/libconfig/)
	* [libprotoc-c](http://code.google.com/p/protobuf-c/) version 0.14 (use --disable-protoc option in its ./configure)

2. Build
	* `./configure`
	* `make`

3. Install
	* `make install`
	* Edit umurmur.conf.example to your liking and put it in a suitable place. /etc/umurmur.conf is default.

4. Run `umurmurd -c <conf file> -p <PID file> -r`. For other switches and their meaning run `umurmurd -h`

A startup script can easily be created if you want to. Just copy an existing script and edit it to your liking.


Support/Contact/Documentation
-----------------------------
See the project page, link above.

Have fun!
