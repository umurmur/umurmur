uMurmurd-Websocket - HTTP/JSON server example
=============================================

HTTP/JSON server in one. Useing a js prettyprinter type lib to display the output
It not the best looking but its just a demo. Hopeing someone else with better web 
skills can make something better.
  

Instructions for building from source
-------------------------------------
1. Requirements
  * [OpenSSL](http://www.openssl.org/)
	* [libwebsockets](http://libwebsockets.org) library. I used this [tarball]([http://git.libwebsockets.org/cgi-bin/cgit/libwebsockets/snapshot/libwebsockets-1.23-chrome32-firefox24.tar.gz) 
  * [Jansson](www.digip.org/jansson/) library.  I used this [tarball](http://www.digip.org/jansson/releases/jansson-2.6.tar.gz) Jansson is a C library for encoding, decoding and manipulating JSON data
  * [CMake](http://cmake.org) 

2. Build - CMake
	* Create a build folder and cd into it
	* `cmake ../`
	* `make`

3. Run
  * start umurmurd from this git like this ./umurmurd -d -c <conf file>
       - the -d option is just to make it easier to see debug info
  * start uMurmurd-Websocket with ./uMurmurd-Websocket --ssl 
       - option --ssl is for https://, http:// otherwise
  * point web browser to https://localhost:7681      

          