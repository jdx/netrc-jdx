# netrc-jdx

A small `.netrc` parser, forked from [netrc-rs](https://github.com/yjhmelody/netrc-rs) 0.1.2.

Differences from upstream:

- Lines whose first non-space character is `#` are comments, as in curl and Python's `netrc`. A `#` elsewhere on a line is kept because it can be part of a password.
- `macdef` bodies are skipped until the next blank line.
- No `no_std` support and no unknown-entry collection.

```rust
let netrc = netrc_jdx::Netrc::parse("machine example.com login me password s3cret")?;
assert_eq!(netrc.credentials("example.com"), Some(("me", "s3cret")));
```

Licensed under MIT or Apache-2.0, as upstream.
