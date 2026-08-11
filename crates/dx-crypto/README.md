# dx-crypto

Cryptographic building blocks for a SaaS backend: secure random, Argon2 hashing,
SHA-256 lookup hashes, API-key / CSRF / invitation tokens, PKCE `S256`, and
AES-256-GCM for secrets at rest.

No async runtime, no storage dependency, no framework — six small modules over
`rand`, `argon2`, `aes-gcm` and `sha2`.

```toml
[dependencies]
dx-crypto = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-crypto-v0.1.0" }
```

## Choosing a hash

This is the decision the crate exists to make explicit:

| you have | use | why |
|---|---|---|
| something a human chose (password, PIN) | `hash_secret` / `verify_secret` | Argon2, salted, deliberately slow — brute force is the threat |
| something already 256-bit random (API key, session token) | `hash_api_key` | unsalted SHA-256, deterministic on purpose so the digest can sit under a unique index and be found in one query |

Salting a random 256-bit token buys nothing and costs you the lookup. Hashing a
password with SHA-256 is a rainbow-table incident waiting to happen.

## What's in it

**Random** — `generate_random_bytes(len)`, `generate_url_safe_token(byte_len)`,
`generate_numeric_otp(len)`. All from OS entropy; the OTP is rejection-sampled,
not `% 10`, so digits stay uniform.

**Hashing** — `hash_secret(&str) -> Result<String>` (PHC-string output),
`verify_secret(hash, secret) -> bool`. Verification returns `false` on a
malformed hash rather than erroring, so a corrupt row can't become a 500.

**Lookup hashes** — `hash_api_key(&str) -> String`, SHA-256 as 43-char
URL-safe base64 (unpadded).

**Tokens** — `generate_api_key()` mints `oat_`-prefixed keys;
`generate_prefixed_api_key("ipk_")` uses your own prefix.
`api_key_prefix` / `prefixed_api_key_prefix` pull the indexable prefix back out
of a key for a two-stage lookup (find by prefix, then verify the hash).
`generate_csrf_token()` and `generate_invitation_token()` are 43-char URL-safe
tokens (256 bits).

**PKCE** — `pkce_s256_challenge(verifier)` builds the challenge;
`verify_pkce_s256(verifier, challenge)` compares in constant time.
`pkce_s256_matches` is a `#[deprecated]` alias of the older non-constant-time
comparison — kept only so existing call sites compile. Under `-D warnings` it is
a build failure, which is the intended nudge.

**Encryption** — `encrypt_secret(plaintext, &key)` / `decrypt_secret(ciphertext,
&key)` with AES-256-GCM; the 12-byte nonce is generated per message and prefixed
to the base64 output. `generate_key()`, `encode_key()` and `parse_key()` handle
the 32-byte key as base64 for config. Decryption validates the nonce length
instead of panicking on a short input.

## Notes

- `API_KEY_PREFIX_LEN` is 12 (`oat_` + 8 random chars). It is public because
  the database column that indexes it needs to agree.
- Every fallible call returns `dx_crypto::Result`. Error variants carry the
  failure reason from the underlying library, never the input value.
- Keys are `[u8; 32]` by type, not `Vec<u8>` — a wrong-length key is a compile
  error where possible and a `Error::InvalidKey` where it isn't.

## License

MIT — see [LICENSE](../../LICENSE).
