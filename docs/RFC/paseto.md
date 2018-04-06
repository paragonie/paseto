% title = "PASETO: Platform-Agnostic SEcurity TOkens"
% abbr = "PASETO"
% category = "info"
% docname = "draft-paragonie-pasetorfc-draft00"
% keyword = ["security", "token"]
%
% date = 2018-04-05T13:00:00Z
%
% [[author]]
% initials="S."
% surname="Arciszewski"
% fullname="Scott Arciszewski"
% organization="Paragon Initiative Enterprises"
%   [author.address]
%   email = "security@paragonie.com"
%   [author.address.postal]
%   country = "United States"

.# Abstract

Platform-Agnostic SEcurity TOkens (PASETO) provides a cryptographically
secure, compact, and URL-safe representation of claims that may be
transferred between two parties. The claims in a PASETO are encoded as
a JavaScript Object (JSON), version-tagged, and either encrypted
or signed using public-key cryptography.

{mainmatter}

# Introduction

Platform-Agnostic SEcurity TOken (PASETO) is a cryptographically secure,
compact, and URL-safe representation of claims intended for space-constrained
environments such as HTTP Cookies, HTTP Authorization headers, and URI
query parameters. PASETOs encode claims to be transmitted in a JSON
[@!RFC7159] object, and is either encrypted or signed using public-key
cryptography.

## Difference Between PASETO and JOSE

The key difference between PASETO and the JOSE family of standards
(JWS [@!RFC7516], JWE [@!RFC7517], JWK [@!RFC7518], JWA [@!RFC7518], and
JWT [@!RFC7519]) is that JOSE allows implementors and users to mix and
match their own choice of cryptographig algorithms (specified by the
"alg" header in JWT), while PASETO has clearly defined protocol versions
to prevent users without a cryptography engineering background from
selecting or permitting an insecure configuration.

PASETO is defined in two pieces:

1. The PASETO Message Format, defined in (#paseto-message-format)
2. The PASETO Protocol Version, defined in (#paseto-protocol-versions)

# Notation and Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**",
"**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this
document are to be interpreted as described in RFC 2119 [@!RFC2119].

Additionally, the key words "**MIGHT**", "**COULD**", "**MAY WISH TO**", "**WOULD
PROBABLY**", "**SHOULD CONSIDER**", and "**MUST (BUT WE KNOW YOU WON'T)**" in
this document are to interpreted as described in RFC 6919 [@!RFC6919].

# PASETO Message Format

Without the Optional Footer:

~~~
version.purpose.payload
~~~

With the Optional Footer:

~~~
version.purpose.payload.footer
~~~

The **version** is a string that represents the current version of the
protocol. Currently, two versions are specified, which each possess
their own ciphersuites. Accepted values: **v1**, **v2**.

The **purpose** is a short string describing the purpose of the token. Accepted values:
**local**, **public**.

* **local**: shared-key authenticated encryption
* **public**: public-key digital signatures; **not encrypted**

Any optional data can be appended to the **footer**. This data is authenticated
through inclusion in the calculation of the authentication tag along with the header
and payload. The **footer** is NOT encrypted.

# PASETO Protocol Versions

PASETO defines two protocol versions, **v1** and **v2**. Each protocol version
strictly defines the cryptographic primitives used. Changes to the primitives
requires new protocol versions.

Both **v1** and **v2** provide authentication of the entire PASETO message,
including the **version**, **purpose**, **payload** and **footer**.


# Additional Associated Data

PASETO uses **Additional Associated Data** to serialize each part of the
message. This provides a deterministic series of bytes for each message
for use in authentication. This is a string of bytes generated from an input
array of byte strings. The output is prefixed by a 64-bit unsigned
little-endian integer of the number of items in the input array. Each byte
string in the input array is then added to the end of the existing output,
each prefixed by a 64-bit unsigned little-endian integer of the length of that
string.

# Version v1

Version **v1** is a compatibility mode comprised of cryptographic primitives
likely available on legacy systems. **v1** **SHOULD NOT** be used when
all systems are able to use **v2**. **v1** **MAY** be used when
when compatibility requirements include systems unable to use cryptographic
primitives from **v2**.

**v1** messages **MUST** use a **purpose**  value of either **local** or
**public**.


# v1.local

**v1.local** messages **SHALL** be encrypted and authenticated with AES-256-CTR
and HMAC-SHA384 using "encrypted-then-MAC".


# Version v2
Version **v2** is the **RECOMMENDED** protocol version. **v2** **SHOULD** be
used in preference to **v1**. Applications using PASETO **SHOULD CONSIDER**
only supporting **v1** messages.

**v2** messages **MUST** use a **purpose**  value of either **local** or
**public**.

# v2.local

**v2.local** messages **MUST** be encrypted with XChaCha20-Poly1305, a variant of
ChaCha20-Poly1305 [@!RFC7539] defined in libsodium that uses a 192-bit nonce.

The **key** **SHALL** be provided by the user. The **key** **MUST** be 32 bytes
long, and **SHOULD** be generated using a cryptographically secure source.
Implementors **SHOULD CONSIDER** providing functionality to generate this
key for users when the implementation can ensure adequate entropy. Any provided
means for generating the **key** **MUST NOT** use poor sources of randomness.

The **nonce** **SHALL** be constructed from a **BLAKE2b** [@!RFC7693]
hash of the **payload**, with a 24 byte randomly generated key parameter and an
output length of 24 bytes. Implementations **SHOULD** use the libsodium
`sodium_crypto_generichash` function when available.

The v2.local ciphertext **SHALL** be constructed using XChaCha20-Poly1305
of the **payload**, using the generated **nonce**, the generated
**Additional Associated Data**, and using the 32 byte **key**. Implementations
**SHOULD** use the libsodium `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt`
and `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt` functions when available.

The **v2.local output** is generated by prepending 'v2.local.' to the
base64url-encoded **v2.local ciphertext** as per the **PASETO Message Format**

# v2.public

**v2.public** messages **MUST** be signed using Ed25519 [@!RFC8032] public key
signatures. These messages provide authentication but do not prevent the
contents from being read, including by those without either the **public key**
or the **private key**.

The **public key** and **private key** **SHOULD** be a valid pair of Ed25519 keys.
Implementations **SHOULD CONSIDER** providing functions to generate the keypair
and **SHOULD** use the `crypto_sign_keypair` libsodium function to do this when
available.

The **v2.public** **signature** is created by generating a byte string containing
the **Additional Associated Data** of the public header (v2.public), the bytes
of the **data**, and the **footer**. The **Additional Associated Data** is then
signed with Ed25519 using the **private key**. Implementations **SHOULD** use
the `crypto_sign_detached` libsodium function to generate this signature when
available.

The **signed payload** is generated by appending the **signature** to the input
data bytes. It is then base64url-encoded.

The **v2.public output** is generated by prepending 'v2.public.' to the
**signed payload** as per the **PASETO Message Format**.

