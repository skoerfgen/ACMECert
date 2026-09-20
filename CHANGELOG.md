## ACMECert v3.7.3
Changes:
- php 8.5 compatibility

## ACMECert v3.7.2
Changes:
- bugfix: check order status before finalize (#66)

## ACMECert v3.7.1
Changes:
- bugfix: getSAN method now also returns 'IP Address' fields, if present.

## ACMECert v3.7.0
Changes:
- added support for IP address certificates
- added option to disable grouping of dns-01 challenges

## ACMECert v3.6.0
Notable changes:
- added support for certificate profile selection:
https://letsencrypt.org/docs/profiles/

## ACMECert v3.5.0
Notable changes:
- getARI now supports Retry-After

## ACMECert v3.4.1
Changes:
- bugfix: getARI did not work with newer OpenSSL versions.

## ACMECert v3.4.0
Notable changes:
- Added support for ACME Renewal Information (ARI)

## ACMECert v3.3.1
Changes:
- Added support for DNS Names (domain names) longer than 64 characters

## ACMECert v3.3.0
Changes:
- added `setLogger()` method to configure logging

## ACMECert v3.2.2
Changes:
- When an instance of ACMECert goes out of scope the garbage collector now reclaims it immediately.

## ACMECert v3.2.1
Changes:
- Fixed deprecation warning since PHP 8 when using [registerEAB](https://github.com/skoerfgen/ACMECert#acmecertregistereab) method.

## ACMECert v3.2.0
Notable changes:
- choosing an arbitrary ACME v2 - RFC 8555 compatible Certificate Authority (CA) is now supported.
- [External Account Binding](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4) support added.
- notBefore / notAfter can be specified if CA supports it.
- retry-after (rate limit) handling.
