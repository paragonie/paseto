# Payload Processing

All PASETO payloads must be a JSON-encoded object represented as a UTF-8 encoded
string. The topmost JSON object should be an object, map, or associative array
(select appropriate for your language), not a flat array.

> **Valid**:
> 
> * `{"foo":"bar"}`
> * `{"foo":"bar","baz":12345,"678":["a","b","c"]}`
>
> **Invalid**:
>
> * `[{"foo":"bar"}]`
> * `["foo"]`
> * `{0: "test"}`

If non-UTF-8 character sets are desired for some fields, implementors are
encouraged to use [Base64url](https://tools.ietf.org/html/rfc4648#page-7)
encoding to preserve the original intended binary data, but still use UTF-8 for
the actual payloads.

## Type Safety with Cryptographic Keys

PASETO library implementations **MUST** implement some means of preventing type
confusion bugs between different cryptography keys. For example:

* Prepending each key in memory with a magic byte to serve as a type indicator
  (distinct for every combination of version and purpose).
* In object-oriented programming languages, using separate classes for each
  cryptography key object that may share an interface or common base class.

It **MUST NOT** be possible for a user to take a known public key (used by
*public* tokens), and generate a *local* token with the same key that any PASETO
implementations will accept.

## Registered Claims

The following keys are reserved for use within PASETO. Users SHOULD NOT write
arbitrary/invalid data to any keys in a top-level PASETO in the list below:

| Key   | Name             | Type     | Example                                                   |
| ----- | ---------------- | -------- | --------------------------------------------------------- |
| `iss` | Issuer           | string   | `{"iss":"paragonie.com"}`                                 |
| `sub` | Subject          | string   | `{"sub":"test"}`                                          |
| `aud` | Audience         | string   | `{"aud":"pie-hosted.com"}`                                |
| `exp` | Expiration       | DateTime | `{"exp":"2039-01-01T00:00:00+00:00"}`                     |
| `nbf` | Not Before       | DateTime | `{"nbf":"2038-04-01T00:00:00+00:00"}`                     |
| `iat` | Issued At        | DateTime | `{"iat":"2038-03-17T00:00:00+00:00"}`                     |
| `jti` | Token Identifier | string   | `{"jti":"87IFSGFgPNtQNNuw0AtuLttPYFfYwOkjhqdWcLoYQHvL"}`  |

In the table above, DateTime means an ISO 8601 compliant DateTime string.

Any other claims can be freely used. These keys are only reserved in the top-level
JSON object.

The keys in the above table are case-sensitive.

Implementors SHOULD provide some means to discourage setting invalid/arbitrary data
to these reserved claims.

### Key-ID Support

Some systems need to support key rotation, but since the payloads of a `local`
token are always encrypted, you can't just drop a `kid` claim inside the payload.

Instead, users should store Key-ID claims (`kid`) in the unencrypted footer. 

For example, if you set the footer to `{"kid":"gandalf0"}`, you can read it without
needing to first decrypt the token (which would in turn knowing which key to use to
decrypt the token).

Implementations should feel free to provide a means to extract the footer from a token,
before decryption, since the footer is used in the calculation of the authentication
tag for the encrypted payload.

Users should beware that, until this authentication tag has been verified, the
footer's contents are not authenticated.

While a key identifier can generally be safely used for selecting the cryptographic
key used to decrypt and/or verify payloads before verification, provided that they
`key-id` is a public number that is associated with a particular key which is not
supplied by attackers, any other fields stored in the footer MUST be distrusted
until the payload has been verified.

**IMPORTANT**: Key identifiers MUST be independent of the actual keys
used by Paseto.

For example, you MUST NOT just drop the public key into the footer for
a `public` token and have the recipient use the provided public key.
Doing so would allow an attacker to simply replace the public key with
one of their own choosing, which will cause the recipient to simply
accept any signature for any message as valid, which defeats the
security goals of public-key cryptography.

Instead, it's recommended that implementors and users use a unique
identifier for each key (independent of the cryptographic key's contents
itself) that is used in a database or other key-value store to select
the apppropriate cryptographic key. These search operations MUST fail
closed if no valid key is found for the given key identifier.

## Future Changes to Payload Processing

The payload processing SHOULD NOT change after version 1.0.0 of the reference
implementation has been tagged, signed, and released; only the cryptography
protocols will receive new versions.

In the event that this turns out to not be true, we will change the first letter
of the version identifier (`v`) to another ASCII-compatible alphanumeric character.

However, we hope to never need to do this.
