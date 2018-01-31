# Common Implementation Details

## Base64 Encoding

Nearly every component in a Paseto (except for the version, purpose, and the `.`
separators) will be encoded using [Base64url](https://tools.ietf.org/html/rfc4648#page-8),
without `=` padding.

This is implemented in our [constant-time RFC 4648 library](https://github.com/paragonie/constant_time_encoding)
as `Base64UrlSafe::encodeUnpadded()`.

## Authentication Padding

Multi-part messages (e.g. header, content, footer) are encoded
in a specific manner before being passed to the respective
cryptographic function.

In `local` mode, this encoding is applied to the additional
associated data (AAD). In `remote` mode, which is not encrypted,
this encoding is applied to the components of the token, with
respect to the protocol version being followed.

The reference implementation resides in `Util::preAuthEncode()`.
We will refer to it as **PAE** in this document (short for
Pre-Authentication Encoding).

### PAE Definition

**PAE()** accepts an array of strings (usually denoted as
`array<int, string>` in docblocks to signify integer keys, but in
other languages, `string[]` is preferred; in the PHP community
they're synonymous).

**LE64()** encodes a 64-bit unsigned integer into a little-endian
binary string.

The first 8 bytes of the output will be the number of pieces. Typically
this is a small number (3 to 5). This is calculated by `LE64()` of the
size of the array.

Next, for each piece provided, the length of the piece is encoded via
`LE64()` and prefixed to each piece before concatenation.

An implementation may look like this:

```javascript
function LE64(n) {
    var str = '';
    for (var i = 0; i < 8; ++i) {
        str += String.fromCharCode(n & 255);
        n = n >>> 8;
    }
    return string;
}
function PAE(pieces) {
    if (!Array.isArray(pieces)) {
        throw TypeError('Expected an array.');
    }
    var count = pieces.length;
    var output = LE64(count);
    for (var i = 0; i < count; i++) {
        output += LE64(pieces[i].length);
        output += pieces[i];
    }
    return output;
}
```

As a consequence:

* `PAE([])` will always return `"\x00\x00\x00\x00\x00\x00\x00\x00"`
* `PAE([''])` will always return 
  `"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"`
* `PAE(['test'])` will always return 
  `"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"`
* `PAE('test')` will throw a `TypeError`

As a result, you cannot create a collision with only a partially controlled
plaintext. Either the number of pieces will differ, or the length of one
of the fields (which is prefixed to the input you can provide) will differ,
or both.

Due to the length being expressed as an unsigned 64-bit integer, it remains
infeasible to generate/transmit enough data to create an integer overflow. 

This is not used to encode data prior to decryption, and no decoding function
is provided or specified. This merely exists to prevent canonicalization
attacks.
