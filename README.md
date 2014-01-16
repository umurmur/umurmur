uMurmur - minimalistic Mumble server
====================================
Project page on [GoogleCode](http://code.google.com/p/umurmur/)

Source hosted on [GitHub](https://github.com/fatbob313/umurmur)

uMurmur is a minimalistic Mumble server primarily targeted to run on embedded computers, like routers, with an open OS like e.g. OpenWRT. The server part of Mumble is called Murmur, hence the name uMurmur. It is available as a precompiled package for quite a lot distributions. Check your distribution's package repository.

Instructions for building from source
-------------------------------------
1. Requirements
	* [OpenSSL](http://www.openssl.org/) or [PolarSSL](http://polarssl.org/) library. For PolarSSL version 1.0.0 and above is required.
	* [libconfig](http://www.hyperrealm.com/libconfig/)
	* [libprotoc-c](http://code.google.com/p/protobuf-c/) version 0.14 or 0.15 (use --disable-protoc option in its ./configure to build only the library). If you for some reason have to run an earlier version you need to recompile the protocol file `Mumble.proto` using the protobuf compiler for the corresponding version.
  * [CMake](http://cmake.org)

2. Build
	* Create a build folder and cd into it
	* `cmake ../` to use default settings (polarssl, no test-cert and /dev/urandom as source for randomness).
	* `make`

3. Install
	* `make install`
	* Edit the umurmur.conf found in the 'etc' folder in the prefix (eg. /usr/local) you installed to.

4. Run `umurmurd -c <conf file> -p <PID file> -r`. For other switches and their meaning run `umurmurd -h`

A startup script can easily be created if you want to. Just copy an existing script and edit it to your liking.

Contributors
------------
* [Antoine Bertin](https://github.com/Diaoul)
* [tilman2](http://code.google.com/u/@UhZTSlBWAxNMWgU%3D/)
* J Sisson - sisson.j ( AT ) gmail DOT com
* [pierre.h](http://code.google.com/u/@VBRUQ1ZTAhNEXwJ9/)
* [phr0z3nt04st](https://github.com/phr0z3nt04st)
* [Troy C](https://github.com/troxor)
* [Trivve](https://github.com/Trivve)
* [hasufell](https://github.com/hasufell)
* [fmorgner](https://github.com/fmorgner)
* [Rawi666](https://github.com/Rawi666)

Hope I didn't forget anyone... Please just send me a mail if you feel this is the case.

Support/Contact/Documentation
-----------------------------
See the project page, link above.

Have fun!
