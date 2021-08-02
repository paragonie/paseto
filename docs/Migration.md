# PASETO Migration Guide

If you were previously using version 1 of our PHP library and want to upgrade to
version 2, this is a list of breaking changes:

* This library now requires PHP 7.1 or newer.
* This library now requires the GMP extension installed.
* The default protocol has been changed from `Version2` to **`Version4`**.
  If you weren't defining this in your code and relying on the default settings,
  you will need to be explicit before you upgrade.

Everything else is a new feature.
