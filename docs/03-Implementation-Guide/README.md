# Implementation Guide

This section of the documentation should serve as a guide for implementors
who seek to bring PASETO to their favorite programming language or framework.

This covers the nitty gritty engineering details, trade-offs, and any questions
whose answers don't fit elegantly in the protocol definition.

## Overview

PASETO is a suite of protocols with distinct [versions](../01-Protocol-Versions).
Each version may impose its own requirements in order to achieve cryptographic
security, so long as the [rules for new versions are followed](https://github.com/paragonie/paseto/tree/master/docs/01-Protocol-Versions#rules-for-current-and-future-protocol-versions).

PASETO can be separated into two distinct parts:

1. The cryptography protocol (defined in the [Protocol Versions section](../01-Protocol-Versions))
   that protects a payload.
2. The payload.

## Sections in This Guide

* [Payload Processing](01-Payload-Processing.md)
* [User-Defined Parser Validation](02-Validators.md)
