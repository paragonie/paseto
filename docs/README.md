# Implementation Details

## PAST Message Format:

### Without the Optional Footer

```
version.purpose.payload
```

The `version` is a string that represents the current version of the protocol. Currently,
two versions are specified, which each possess their own ciphersuites. Accepted values:
`v1`, `v2`.

The `purpose` is a short string describing the purpose of the token. Accepted values:
`enc`, `auth`, `sign`.

The `payload` is a base64url-encoded string that contains the data that is secured. It may be
encrypted. It may use public-key cryptography. It MUST be authenticated or signed. Encrypting
a message using PAST implicitly authenticates it.

### With an Optional Footer

```
version.purpose.payload.optional
version.purpose.one-time-key.ciphertext.optional (sealing only)
```

Any `optional` data can be appended to the end. This information is public (unencrypted), even
if the payload is encrypted. However, it is always authenticated. It's always base64url-encoded.

 * For encrypted tokens, it's included in the associated data alongside the nonce.
 * For authenticated/signed tokens, it's appended to the message during the actual
   authentication/signing step.

## Versions and their Respective Purposes

See [Protocol Versions](01-Protocol-Versions) for specifics.

## How should we pronounce PAST?

Like the English word "pasta" without the final "a". It rhymes with "frost"
and the first syllable in "roster".

Pronouncing it like the English word "past" is acceptable, but
politely discouraged.

Implementations in other languages are encouraged, but not required,
to make pasta puns in their naming convention.
