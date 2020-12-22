# libre Changelog

All notable changes to libre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- .gitignore: add ctags and vim swp files to gitignore [#31]
- tls: add tls_add_capem() for adding CA cert as PEM string [#33]
- httpauth: Add digest support for http clients [#33]
- httpauth: Add basic authentication for HTTP clients [#33]
- dns: add set function for DNS config [#33]
- http/client: support IPv6 [#33]
- http/client: use const parameter for set laddr(6) functions [#33]
- http/client: add set function for timeout [#33]
- http/client: add http_client_add_capem() [#33]
- http/client: add set functions for client certificate and private key [#33]
- http: add HTTP request connection with authorization [#33]
- http: setting of timeouts for http client [#35]
- http: set default path for http requests [#35]
- tls: set selfsigned Elliptic Curve (EC) function [#17]
- tls: extend server verification by host name check (SNI) [#45]
- jbuf: adapative jitter buffer [#41]
- tmr: add tmr_jiffies_usec() - get accurate microseconds [#52]
- fmt: add pl_i32() that converts pl to int32_t [#60]
- fmt: add pl_i64() that converts pl to int64_t [#60]
- mk/re: add C11 and Atomic detection [#61]

### Removed

- openssl: remove obsolete function tls_set_hostname() [#33]
- mk/re: remove gcc 2.x/3.x support [#58]

### Changed

- http/client: cleanup doxygen [#33]
- http/client: use host of http_req for the host name validation [#37]
- main: disable MAIN_DEBUG, TMR_DEBUG and increase MAX_BLOCKING to 500ms [#43]
- sipreg: dont't force digest challenge for register [#49]
- mk/re: do not override LIBRE_INC, LIBRE_SO and LIBRE_PATH [#62]

### Fixed

- dns/client: fix HAVE_INET6 and win32/vcxproj: updates [#28]
- http: fix segfault in response.c [#35]
- http/request: parameter NULL check for http_reqconn_send() [#37]
- http/client: fix conn_idle [#46]
- http/httpreq: mem leak fix [#47]
- sip/request: fix msg->scode null pointer dereference
- rtmp/conn: initialize err
- mk/re: fix LIBRE_SO static detection
- dns/res: Properly process IPV4 and IPV6 addresses (DARWIN) [#56]
- sip/keepalive: fix codeql cpp/integer-multiplication-cast-to-long
- fmt/time: fix codeql gmtime warning
- mk/re: fix gcc 4.x and newer compiler warnings


## [v1.1.0] - 2020-10-04

### Added

- tls: functions to get the certificate issuer and subject [#18]
- uri: Added path field to struct uri and its decode to uri_decode [#22]
- tcp: add tcp_connect_bind [#24]
- http: support bind to laddr in http_request [#24]
- sipreg: support Cisco REGISTER keep-alives [#19]
- sip: websocket support [#26]

### Fixed

- tls/openssl: fix X509_NAME win32/wincrypt.h conflict
- dns: listen on IPv4 and IPv6 socket [#27]
- main: fix/optimize windows file descriptors [#25]

### Contributors (many thanks)

- Alfred E. Heggestad
- Christian Spielberger
- Christoph Huber
- Franz Auernigg
- Juha Heinanen
- johnjuuljensen
- Sebastian Reimers


## [v1.0.0] - 2020-09-08

### Added

- sip: add trace
- sdp: sdp_media_disabled API function [#2]
- tls: add tls_set_selfsigned_rsa [#6]
- tls: add functions to verify server cert, purpose and hostname [#10]
- http: client should set SNI [#10]
- http: client should use tls functions to verify server certs, purpose
  and hostname [#10]
- sipreg: add proxy expires field and get function [#13]
- sipreg: make re-register interval configurable [#13]

### Changed

- debian: Automatic cleanup after building debian package

### Fixed

- Set SDK path (SYSROOT) using xcrun (fix building on macOS 10.14)
- tcp: close socket on windows if connection is aborted or reset [#1]
- rtmp: Fix URL path parsing (creytiv#245)
- ice: various fixes [baresip/baresip#925]
- openssl/tls: replace deprecated openssl 1.1.0 functions [#5]

### Contributors (many thanks)

- Alfred E. Heggestad
- Christian Spielberger
- Christoph Huber
- Franz Auernigg
- juha-h
- Juha Heinanen
- Richard Aas
- Sebastian Reimers


[#61]: https://github.com/baresip/re/pull/61
[#62]: https://github.com/baresip/re/pull/62
[#60]: https://github.com/baresip/re/pull/60
[#58]: https://github.com/baresip/re/pull/58
[#56]: https://github.com/baresip/re/pull/56
[#52]: https://github.com/baresip/re/pull/52
[#49]: https://github.com/baresip/re/pull/49
[#47]: https://github.com/baresip/re/pull/47
[#46]: https://github.com/baresip/re/pull/46
[#45]: https://github.com/baresip/re/pull/45
[#43]: https://github.com/baresip/re/pull/43
[#41]: https://github.com/baresip/re/pull/41
[#37]: https://github.com/baresip/re/pull/37
[#35]: https://github.com/baresip/re/pull/35
[#33]: https://github.com/baresip/re/pull/33
[#31]: https://github.com/baresip/re/pull/31
[#28]: https://github.com/baresip/re/pull/28
[#27]: https://github.com/baresip/re/pull/27
[#26]: https://github.com/baresip/re/pull/26
[#25]: https://github.com/baresip/re/pull/25
[#19]: https://github.com/baresip/re/pull/19
[#24]: https://github.com/baresip/re/pull/24
[#22]: https://github.com/baresip/re/pull/22
[#18]: https://github.com/baresip/re/pull/18
[#17]: https://github.com/baresip/re/pull/17
[#13]: https://github.com/baresip/re/pull/13
[#10]: https://github.com/baresip/re/pull/10
[#6]: https://github.com/baresip/re/pull/6
[#5]: https://github.com/baresip/re/pull/5
[#2]: https://github.com/baresip/re/pull/2
[#1]: https://github.com/baresip/re/pull/1

[v1.0.0]: https://github.com/baresip/re/compare/v0.6.1...v1.0.0
[v1.1.0]: https://github.com/baresip/re/compare/v1.0.0...v1.1.0
[Unreleased]: https://github.com/baresip/re/compare/v1.1.0...HEAD
