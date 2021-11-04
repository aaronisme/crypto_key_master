# Crypto key master


crypto_key_master is the rust library for helping manage crypto keys

[![Crates.io][crates-badge]][crates-url]

[crates-badge]: https://img.shields.io/crates/v/crypto_key_master.svg
[crates-url]: https://crates.io/crates/crypto_key_master

[Documentation](https://docs.rs/crypto_key_master)

## Usage

To use `crypto_key_master`, first add this to your `Cargo.toml`:

```toml
[dependencies]
crypto_key_master = "0.1.2"
```

Next, add this to your crate:

```rust
use crypto_key_master::{KeyMaster, SignRequest, Curve};
let mut key_master = KeyMaster {};
let entropy = key_master.generate_entropy(32).unwrap();
let key_id = key_master.write_seed("123", "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4".to_string()).unwrap();
let request = SignRequest { path: "m/44'/0'/0'/0/0", unsigend_data: "hello".as_bytes().to_vec(), key_id: "123456", curve: Curve::Secp256k1};
let sig = key_master.sign(request, "123").unwrap();
```


## License

This project is licensed under the [MIT license](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `crypto_key_master` by you, shall be licensed as MIT, without any additional
terms or conditions.
