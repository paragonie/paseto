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

## Optional Footer

PASETO places no restrictions on the contents of the authenticated footer.
The footer's contents **MAY** be JSON-encoded (as is the payload), but it
doesn't have to be.

The footer contents is intended to be free-form and application-specific.

### Storing JSON in the Footer

Implementations that allow users to store JSON-encoded objects in the footer
**MUST** give users some mechanism to validate the footer before decoding.

Some example parser rules include:

1. Enforcing a maximum length of the JSON-encoded string.
2. Enforcing a maximum depth of the decoded JSON object.
   (Recommended default: Only 1-dimensional objects.)
3. Enforcing the maximum number of named keys within an object.

The motivation for these additional rules is to mitigate the following
security risks:

1. Stack overflows in JSON parsers caused by too much recursion.
2. Denial-of-Service attacks enabled by hash-table collisions.

#### Enforcing Maximum Depth Without Parsing the JSON String

Arbitrary-depth JSON strings can be a risk for stack overflows in some JSON
parsing libraries. One mitigation to this is to enforce an upper limit on the
maximum stack depth. Some JSON libraries do not allow you to configure this
upper limit, so you're forced to take matters into your own hands.

A simple way of enforcing the maximum depth of a JSON string without having
to parse it with your JSON library is to employ the following algorithm:

1. Create a copy of the JSON string with all `\"` sequences and whitespace
   characters removed.
   This will prevent weird edge cases in step 2.
2. Use a regular expression to remove all quoted strings and their contents.
   For example, replacing `/"[^"]+?"([:,\}\]])/` with the first match will 
   strip the contents of any quoted strings.
3. Remove all characters except `[`, `{`, `}`, and `]`.
4. If you're left with an empty string, return `1`. 
5. Initialize a variable called `depth` to `1`.
6. While the stripped variable is not empty **and** not equal to the output
   of the previous iteration, remove all `{}` and `[]` pairs, then increment 
   `depth`.
7. If you end up with a non-empty string, you know you have invalid JSON:
   Either you have a `[` that isn't paired with a `]`, or a `{` that isn't
   paired with a `}`. Throw an exception.
8. Return `depth`.

An example of this logic implemented in TypeScript is below:

```typescript
function getJsonDepth(data: string): number {
    // Step 1
    let stripped = data.replace(/\\"/g, '').replace(/\s+/g, '');
    
    // Step 2
    stripped = stripped.replace(/"[^"]+"([:,\}\]])/g, '$1');
    
    // Step 3
    stripped = stripped.replace(/[^\[\{\}\]]/g, '');
    
    // Step 4
    if (stripped.length === 0) {
        return 1;
    }
    // Step 5
    let previous = '';
    let depth = 1;
    
    // Step 6
    while (stripped.length > 0 && stripped !== previous) {
        previous = stripped;
        stripped = stripped.replace(/({}|\[\])/g, '');
        depth++;
    }
    
    // Step 7
    if (stripped.length > 0) {
        throw new Error(`Invalid JSON string`);
    }
    
    // Step 8
    return depth;
}
```

#### Enforcing Maximum Key Count Without Parsing the JSON String

Hash-collision Denial of Service attacks (Hash-DoS) is made possible by
creating a very large number of keys that will hash to the same value,
with a given hash function (e.g., djb33).

One mitigation strategy is to limit the number of keys contained within
an object (at any arbitrary depth).

The easiest way is to count the number of times you encounter a `":`
token that isn't followed by a backslash (to side-step corner-cases where
JSON is encoded as a string inside a JSON value).

Here's an example implementation in TypeScript:

```typescript
/**
 * Split the string based on the number of `":` pairs without a preceding
 * backslash, then return the number of pieces it was broken into.
 */
function countKeys(json: string): number {
    return json.split(/[^\\]":/).length;
}
```

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

[PASERK](https://github.com/paseto-standard/paserk), a PASETO extension, defines a
universal and unambiguous way to calculate key identifiers for a PASETO key. See
[the specification for PASERK's `ID` operation](https://github.com/paseto-standard/paserk/blob/master/operations/ID.md)
for more information. PASERK is the **RECOMMENDED** way to serialize Key IDs.

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
