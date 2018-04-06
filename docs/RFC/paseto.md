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

Any optional data can be appended to the end. This information is NOT encrypted, but it
is used in calculating the authentication tag for the payload. It's always base64url-encoded.

# PASETO Protocol Versions
