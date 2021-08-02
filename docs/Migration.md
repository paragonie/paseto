# PASETO Migration Guide

If you were previously using version 1 of our PHP library and want to upgrade to
version 2, this is a list of breaking changes:

* This library now requires PHP 7.1 or newer.
* This library now requires the GMP extension installed.
* The default protocol has been changed from `Version2` to **`Version4`**.
  If you weren't defining this in your code and relying on the default settings,
  you will need to be explicit before you upgrade.

Everything else is a new feature.

## Cryptographic Keys

While it is *possible* to copy cryptographic key material across versions (especially
symmetric keys for all versions, but also asymmetric keys between Version 2 and
Version 4), we strongly recommend that nobody does this.

One of the core assumptions in PASETO's design is that a single cryptography key is
only ever used with a single version and purpose. This is why we emphasize type
safety.

Copying the underlying raw key material from one version to another isn't known to
cause any vulnerabilities, but you're putting yourself in risky territory, and
future security research **MAY** yield cross-protocol attacks that work against
your system. 

Cryptography keys are cheap. Just generate new ones for your new versions.
