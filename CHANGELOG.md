# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2025-04-15

### Added

- Per-channel setting to explicitly allow temporary channel creation.
- GitHub Actions and Docker CI ([#200](https://github.com/umurmur/umurmur/pull/200)).
- GnuTLS in the build pipeline ([#209](https://github.com/umurmur/umurmur/pull/209)).

### Changed

- Namespace the default configuration file location ([#170](https://github.com/umurmur/umurmur/pull/170)) (dvzrv).
- CMake finds libraries more reliably and installs to `/sbin` ([#199](https://github.com/umurmur/umurmur/pull/199)).
- Drop privileges whenever a user is configured, not only when daemonizing ([#201](https://github.com/umurmur/umurmur/pull/201)).
- Raise the CMake minimum version and add a Debug build option.
- Use Debian Stable for CI builds ([#208](https://github.com/umurmur/umurmur/pull/208)).

### Fixed

- `initgroups(3)` invalidating data returned by `getgrnam(3)` ([#183](https://github.com/umurmur/umurmur/pull/183)) (omar-polo).
- Too few arguments to a formatting function ([#204](https://github.com/umurmur/umurmur/pull/204)).
- Clearer `initgroups()` error message ([#206](https://github.com/umurmur/umurmur/pull/206)).
- Segfault when the client does not provide OS information.

## [0.3.0] - 2025-01-28

### Added

- Mbed TLS 3.x support (Glenn Strauss).

### Fixed

- OpenSSL compatibility with Mumble clients that require TLS 1.3 ciphers (Petre Rodan).

## [0.2.20] - 2021-03-21

### Fixed

- OpenSSL compilation against a library built without deprecated APIs (Rosen Penev).

## [0.2.19] - 2021-01-23

### Fixed

- CMake install location for the config file (dvzrv).
- Do not use ECC when OpenSSL is compiled without support for it.

## [0.2.18] - 2020-12-31

### Added

- Priority speaker support (unterwulf).
- OpenSSL EC-key support. Note that some clients (for example Mumla on Android) do not handle this (fatbob313).

### Changed

- mbedTLS error reporting and deprecated-API handling (fatbob313).
- Remove duplicated and unused code (unterwulf).
- Log the OpenSSL version at init time (fatbob313).
- Update the OpenSSL cipher list (fatbob313).
- Regenerate protobuf files with protoc-c 1.3.3.

### Fixed

- Possible segmentation fault from authenticating clients too early (unterwulf).
- Default config file location when building with CMake.
- Always forward speech to linked channels, not only when whispering or screaming (fatbob313).
- Build against OpenSSL without the 1.1 API enabled (Eneas U de Queiroz).
- Do not generate a cert and key when the files are present but unusable or unreadable (unterwulf).
- Compiler warnings (Rosen Penev).
- Nonce and crypt handling (feinerer).
- Autotools deprecation warning (C4K3).
- Automake dist target (unterwulf).
- Various fixes (doctaweeks, concatime).

## [0.2.17] - 2017-04-29

Stable release of 0.2.17rc1.

## [0.2.17rc1] - 2017-02-06

### Added

- Support for mbed TLS >= 2 (Rawi666, l2dy). Enable with `--with-ssl=mbedtls` (Autotools) or `-DSSL=mbedtls` (CMake).
- Configuration option to hide IP addresses from clients (C4K3). Set `show_addresses = false;` to hide addresses.
- Export the client hash in the SHM interface (snowblind).

### Fixed

- Multiple possible NULL pointer dereferences (TinnedTuna).
- Set the scheduler policy before switching users (C4K3).
- Set up TLS infrastructure before switching users (Nauxuron).
- Default `bindport6` to `bindport` if it is not set explicitly (C4K3).
- Default to modern TLS cipher suites (l2dy, adufray).
- Do not leave garbage when setting socket options (pfmooney).
- Replace a stray `bool` with `bool_t` (andres-erbsen).
- Restrict TLS connections to TLS >= 1.0 (fmorgner).

## [0.2.16a] - 2015-06-20

### Fixed

- Crash in the SHM API during update (doctaweeks).
- Failure to detect missing IPv6 support in FreeBSD jails (marcusball).
- Compile-time check for availability of `version_get_string` (fatbob313).

## [0.2.16] - 2015-04-07

### Added

- Shared-memory API (snowblind). Enable with `--with-shmapi` (Autotools) or `-DENABLE_SHAREDMEMORY_API=on` (CMake). See [umurmur-monitor](https://github.com/umurmur/umurmur-monitor) for an example client.
- GnuTLS backend (fmorgner).
- SELinux type-enforcement rules (fmorgner), published at [umurmur-selinux](https://github.com/umurmur/umurmur-selinux).

### Fixed

- Reworked timestamping (fatbob313).
- Banning when using IPv6 (fatbob313 and fmorgner).

## [0.2.15] - 2014-08-08

### Added

- IPv6 dual-stack support (fmorgner).
- CMake build system alongside Autotools (fmorgner).

### Changed

- Update to Protobuf-C 1.0.0.

## [0.2.14] - 2014-01-02

### Added

- `silent` option for channel configuration.
- `position` option for channel configuration.
- PolarSSL 1.3.x support.
- Support for PolarSSL built with zlib.
- Certificate chain delivery for OpenSSL via the new `ca_path` option.

### Changed

- Use `CLOCK_MONOTONIC` instead of `gettimeofday()`, which can misbehave if the clock jumps (for example after NTP sync).

## [0.2.13] - 2013-06-09

### Added

- Timestamps when logging to a file.

### Fixed

- Opus not working.

## [0.2.12] - 2013-05-20

### Fixed

- Crash at client disconnect with PolarSSL >= 1.2.6.
- Use of `/dev/urandom` for random numbers (PolarSSL).

## [0.2.11] - 2013-05-13

### Added

- Mumble protocol 1.2.4 support.
- Opus codec support.
- Config option for the Opus threshold.
- PolarSSL 1.2.x support.
- Autoconf `./configure` switches:
  - `--enable-polarssl-test-certificate` — use and link the PolarSSL test certificate. Off by default; umurmurd exits with an error if no certificate and/or key file is found.
  - `--enable-polarssl-havege` — use PolarSSL's HAVEGE random number generator. Defaults to `/dev/urandom`.

### Removed

- Support for PolarSSL versions prior to 1.0.0.

### Fixed

- Disconnect when using PTT.
- Possible crash when many clients disconnect simultaneously.
- Error message at client disconnect when using OpenSSL.

## [0.2.10] - 2012-03-18

### Changed

- Update the version string everywhere.
- Better logging when a connection fails.

## [0.2.9] - 2012-03-17

### Added

- PolarSSL 1.1.x support.
- Admin user via token password.
- Mute, deafen, kick, and optional ban for the admin user.
- Optional banlist persistence to a file.
- Bans via IP and user certificate.
- Banlist editing in Mumble.
- Option to disallow text messages.
- Release codename.

### Fixed

- Compile on \*BSD (J Sisson).
- Building on OS X.
- Self-deafen also self-mutes.

## [0.2.8] - 2011-10-11

### Added

- Channel passwords (`password = "<password>";` in the channel configuration).
- PolarSSL 1.x.x support (0.x.x remains supported).
- Configuration test flag (`-t`).

### Removed

- Pointless CA cert handling with PolarSSL (it did not work).

### Fixed

- Portability issues in the configure script, including adding `poll.h` to header checks.
- Unnecessary fatal exit when a client is disconnected due to an SSL error.

## [0.2.7] - 2011-04-18

### Added

- Autotools build system (Diaoul).
- Configuration option to log to a file.

### Fixed

- Codec alpha/beta in the message sent to the client.

### Changed

- Miscellaneous cleanup.

## [0.2.6] - 2011-02-09

### Added

- Privilege dropping, enabled in the config file (tilman2).
- Mumble protocol 1.2.3.
- UserStats message support.
- Recording support.

### Fixed

- PID file handling and various other fixes (tilman2).
- BSD portability (J Sisson).

### Changed

- Configuration file errors now go to the log instead of stderr.

## [0.2.5] - 2010-11-13

### Added

- Bind IP and port command-line parameters.

### Changed

- Warn instead of exiting fatally when setting TOS on the UDP socket fails.
- Update Protobuf-C to 0.14.

### Fixed

- Mute/unmute status not showing correctly in other clients' GUIs.
- False "authenticated" status showing for other clients.

## [0.2.4] - 2010-03-24

### Fixed

- Broken Makefile in the 0.2.3 release.

## [0.2.3] - 2010-03-24

### Fixed

- Byte-order handling so uMurmur works on big-endian platforms.

## [0.2.2] - 2010-03-07

### Fixed

- Crash when a user adds an Access Token while connected.
- Crash when dragging the self user from a temporary channel and dropping it back into the same channel.

## [0.2.1] - 2010-02-17

### Fixed

- Version string left at `0.2.0-beta2` in the 0.2.0 release.

## [0.2.0] - 2010-02-17

### Added

- Mumble protocol 1.2.x (1.2.x clients are supported).
- PolarSSL as an alternative to OpenSSL.
- Whisper targets for channels, channel trees, and linked channels.
- Temporary channels created by users.
- Channel links in the configuration file.
- Non-enterable channels in the configuration file.

### Changed

- Strip positional audio if users are not in the same plugin context (not playing the same game).

## [0.1.3] - 2009-11-18

### Added

- Command-line switch to enable realtime priority.

### Fixed

- TCP-mode memory leak.

## [0.1.2] - 2009-09-26

### Changed

- Increase max string size.
- Force a close when the inactivity timer triggers.
- Correct log levels.

## [0.1.1] - 2009-08-29

### Added

- Initial release.

[0.3.1]: https://github.com/umurmur/umurmur/compare/0.3.0...v0.3.1
[0.3.0]: https://github.com/umurmur/umurmur/compare/0.2.20...0.3.0
[0.2.20]: https://github.com/umurmur/umurmur/compare/0.2.19...0.2.20
[0.2.19]: https://github.com/umurmur/umurmur/compare/0.2.18...0.2.19
[0.2.18]: https://github.com/umurmur/umurmur/compare/0.2.17...0.2.18
[0.2.17]: https://github.com/umurmur/umurmur/compare/0.2.17rc1...0.2.17
[0.2.17rc1]: https://github.com/umurmur/umurmur/compare/0.2.16a...0.2.17rc1
[0.2.16a]: https://github.com/umurmur/umurmur/compare/0.2.16...0.2.16a
[0.2.16]: https://github.com/umurmur/umurmur/compare/0.2.15...0.2.16
[0.2.15]: https://github.com/umurmur/umurmur/compare/0.2.14...0.2.15
[0.2.14]: https://github.com/umurmur/umurmur/compare/0.2.13...0.2.14
[0.2.13]: https://github.com/umurmur/umurmur/compare/0.2.12...0.2.13
[0.2.12]: https://github.com/umurmur/umurmur/compare/0.2.11...0.2.12
[0.2.11]: https://github.com/umurmur/umurmur/compare/0.2.10...0.2.11
[0.2.10]: https://github.com/umurmur/umurmur/compare/0.2.9...0.2.10
[0.2.9]: https://github.com/umurmur/umurmur/compare/0.2.8...0.2.9
[0.2.8]: https://github.com/umurmur/umurmur/compare/0.2.7...0.2.8
[0.2.7]: https://github.com/umurmur/umurmur/compare/0.2.6...0.2.7
[0.2.6]: https://github.com/umurmur/umurmur/compare/0.2.5...0.2.6
[0.2.5]: https://github.com/umurmur/umurmur/compare/0.2.4...0.2.5
[0.2.4]: https://github.com/umurmur/umurmur/compare/0.2.3...0.2.4
[0.2.3]: https://github.com/umurmur/umurmur/compare/0.2.2...0.2.3
[0.2.2]: https://github.com/umurmur/umurmur/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/umurmur/umurmur/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/umurmur/umurmur/compare/0.1.3...0.2.0
[0.1.3]: https://github.com/umurmur/umurmur/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/umurmur/umurmur/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/umurmur/umurmur/releases/tag/0.1.1
