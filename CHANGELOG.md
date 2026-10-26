# srptools changelog


### Unreleased
* !! Drop Python 2 support.
* !! Massive refactor for Python 3.10+.
* ** Add hidden CLI secret input and warn about sensitive arguments and diagnostic output (#13).
* ** Correct mutual-authentication examples and keep checks active under Python optimization (#13).
* ** Derive binary verifiers from the exact returned salt bytes (#13).
* ** Fix CLI callbacks, registration presets and help command names (#13).
* ** Use timing-resistant comparison for hex and Base64 session proofs (#13).

### v1.0.1 [2020-09-12]
* !! Dropped QA for Python 2.
* ** Now context.get_common_password_hash handles inner hashes with leading zeros correctly.


### v1.0.0
* !! Dropped QA for Python 3.3 and 3.4.
* No functional changes. Celebrating 1.0.0.


### v0.2.0
* ** Fixed unable to install into envs with 'six' unavailable
* ++ Added 'preset' CLI option
* ** Improved compatibility with other implementations.


### v0.1.1
* ** Hex strings are now even-length.
* ** Fixed shareable hashed values with leading zeros issue.


### v0.1.0
* ++ Basic functionality.
