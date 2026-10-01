## Overview

**cure_asn1** is a Rust library designed for parsing objects encoded in ASN.1 format, as well as handling RRDP objects. 
The library is built for efficiency and flexibility: **It does not enforce any structure or validation checks**. It will parse any well-formated DER/BER encoded object.

Note: This tool is part of the **CURE  Toolchain**.


---

## Features

- 📜 **ASN.1 Parsing**: Decode and parse any object encoded ASN.1. Support for DER, CER, BER.
- 🌐 **RPKI Support**: Handle all currently defined RPKI objects (TAL, CER, MFT, ROA, CRL, GBR, ASPA) and RRDP objects (Notification, Snapshot, Delta).
- ⚡ **High Performance**: Built in Rust for speed and reliability.
- 🛠️ **Customizable**: Extend and integrate the library into your own tools. 


## Installation

You can install the cure_asn1 by cloning the repository and building it manually:

```bash
git clone https://github.com/niklbird/cure_asn1.git
cd cure_asn1

cargo build --release
```

Integrate the library into your own project through Cargo
```bash
cure_asn1 = {path="path/to/cure_asn1/"}
```

## Usage
Parse RPKI objects by calling 
```rust
cure_asn1::rpki::parse_rpki_object(). 
```

Each object is represented as a labled Abstract Syntax Tree (*tree_parser::Tree*). Access a field of the tree through its *label* or its *tree node*.
For RPKI objects, we provide basic functionality to access most important object fields in 
```rust
rpki::RPKIObject 
```

## Disclaimer

This library is intended for research purposes only. We do not guarantee correctness of parsing results and the tool **should not be used for production operations**.
The design of the library was motivated by requirements of the **CURE Fuzzer** and might not fit your use-case. 


## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-xyz`).
3. Commit your changes (`git commit -m "Add feature XYZ"`).
4. Push to your branch (`git push origin feature-xyz`).
5. Open a pull request.

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

⭐ **If you find this project useful, consider giving it a star!** ⭐
