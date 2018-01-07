# Implementation Details

## PAST Message Format:

### Without the Optional Footer

```
version.purpose.payload.footer
```

The `version` is a string that represents the current version of the protocol. Currently,
two versions are specified, which each possess their own ciphersuites. Accepted values:
`v1`, `v2`.

The `purpose` is a short string describing the purpose of the token. Accepted values:
`local`, `public`.

* `local`: shared-key authenticated encryption
* `public`: public-key digital signatures; **not encrypted**

Any optional data can be appended to the end. This information is NOT encrypted, but it
is used in calculating the authentication tag for the payload. It's always base64url-encoded.

 * For local tokens, it's included in the associated data alongside the nonce.
 * For public tokens, it's appended to the message during the actual
   authentication/signing step, in accordance to
   [our standard format](https://github.com/paragonie/past/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding).

Thus, if you want unencrypted, but authenticated, tokens, you can simply set your payload
to an empty string and your footer to the message you want to authenticate.

## Versions and their Respective Purposes

See [Protocol Versions](01-Protocol-Versions) for specifics.

## How should we pronounce PAST?

Like the English word "pasta" without the final "a". It rhymes with "frost"
and the first syllable in "roster".

Pronouncing it like the English word "past" is acceptable, but
politely discouraged.

Implementations in other languages are encouraged, but not required,
to make pasta puns in their naming convention.
