# Common Implementation Details

## Authentication Padding

Multi-part messages (e.g. header, content, footer) are encoded
in a specific manner before being passed to the respective
cryptographic function.

For encrypted modes (`enc` and `seal`), this encoding is applied
to the additional associated data (AAD). For unencrypted modes,
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

As a result, you cannot create a collision with only a partially controlled
plaintext. Either the number of pieces will differ, or the length of one
of the fields (which is prefixed to the input you can provide) will differ,
or both.

Due to the length being expressed as an unsigned 64-bit integer, it remains
infeasible to generate/transmit enough data to create an integer overflow. 

This is not used to encode data prior to decryption, and no decoding function
is provided or specified. This merely exists to prevent canonicalization
attacks.
