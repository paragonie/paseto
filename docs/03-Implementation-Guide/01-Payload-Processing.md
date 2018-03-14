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
> * `["foo"]`
> * `{0: "test"}`

If non-UTF-8 character sets are desired for some fields, implementors are
encouraged to use [Base64url](https://tools.ietf.org/html/rfc4648#page-7)
encoding to preserve the original intended binary data, but still use UTF-8 for
the actual payloads.
