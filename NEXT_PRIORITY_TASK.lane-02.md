# Next Priority Task

Reject mismatched PartStore digests.

`PartStore::put_bytes_with_digest` is public and currently trusts the caller-supplied
BLAKE3 digest when placing bytes in the content-addressed store. Internal callers
compute the digest first, but an external caller can write bytes under the wrong
digest and violate the PartStore immutability/content-addressing contract.

Suggested scope:

- Update `crates/omnisstream/src/part_store.rs` so `put_bytes_with_digest` validates
  that `blake3_256_bytes(bytes)` matches the supplied digest before writing.
- Return an `io::ErrorKind::InvalidInput` error on mismatch to avoid adding a public
  error enum.
- Add a unit test that attempts to store bytes with a digest computed from different
  bytes and confirms no file is created for the supplied digest.

Suggested validation:

- `cargo test -p omnisstream part_store::tests --all-features`
- `cargo clippy --all-targets --all-features -- -D warnings`
