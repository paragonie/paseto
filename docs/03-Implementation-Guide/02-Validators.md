# Validators

After verifying and extracting the payloads from the token, but before returning
the object representation of the payload to the user, library authors may wish to
add the ability for their token parsers to automatically validate the token against
some basic constraints.

This is not strictly required, but validation support is highly recommended.

Some examples of validation rules that libraries may wish to provide include:

* `ForAudience` which compares the payload-provided `aud` claim with an expected
   value.
* `IdentifiedBy` which compares the payload-provided `jti` claim with an expected
   value.
* `IssuedBy` which compares the payload-provided `iss` claim with an expected
   value.
* `NotExpired` which verifies that the current time is less than or equal to the
   DateTime stored in the `exp` claim.
* `Subject` which compares the payload-provided `sub` claim with an expected
   value.
* `ValidAt` which verifies all of the following:
   * The current time is less than or equal to the DateTime stored in the `exp` claim.
   * The current time is greater than or equal to the DateTime stored in the `iat` claim.
   * The current time is greater than or equal to the DateTime stored in the `nbf` claim.

Example implementations of these validators are included in the PHP implementation.

Validation should fail-closed by default (e.g. if invalid data is provided).
