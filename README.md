# uMurmur
 
[![Linux](https://github.com/umurmur/umurmur/actions/workflows/portability-linux.yml/badge.svg)](https://github.com/umurmur/umurmur/actions/workflows/portability-linux.yml)
[![macOS](https://github.com/umurmur/umurmur/actions/workflows/portability-macos.yml/badge.svg)](https://github.com/umurmur/umurmur/actions/workflows/portability-macos.yml)
[![FreeBSD](https://github.com/umurmur/umurmur/actions/workflows/portability-freebsd.yml/badge.svg)](https://github.com/umurmur/umurmur/actions/workflows/portability-freebsd.yml)
[![OpenBSD](https://github.com/umurmur/umurmur/actions/workflows/portability-openbsd.yml/badge.svg)](https://github.com/umurmur/umurmur/actions/workflows/portability-openbsd.yml)
[![NetBSD](https://github.com/umurmur/umurmur/actions/workflows/portability-netbsd.yml/badge.svg)](https://github.com/umurmur/umurmur/actions/workflows/portability-netbsd.yml)
 
uMurmur is a minimalistic Mumble server primarily targeted to run on embedded computers, like routers, with an open OS like e.g. OpenWRT. The server part of Mumble is called Murmur, hence the name uMurmur. It is available as a precompiled package for quite a lot distributions. Check your distribution's package repository.
 
## Building

Compiling uMurmur requires CMake, libconfig, protobuf-c, and one supported TLS library.

```shell
cmake -S . -B build -DSSL=openssl -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
sudo cmake --install build
```

`-DSSL` selects the TLS implementation: `openssl` (default, also LibreSSL), `mbedtls`, or `gnutls`.

To list the other configuration options and their current values, run `cmake -LH build` after configuring, or edit them interactively with `ccmake build` or `cmake-gui`.
 
## Contributors

<a href="https://github.com/umurmur/umurmur/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=umurmur/umurmur" alt="Contributors"/>
</a>

## Support

Bug reports: [Issues](https://github.com/umurmur/umurmur/issues) or [Pull Requests](https://github.com/umurmur/umurmur/pulls)

Future enhancements: [Discussions](https://github.com/umurmur/umurmur/discussions)
