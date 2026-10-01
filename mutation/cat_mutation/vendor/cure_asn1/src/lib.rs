//! # cure_asn1
//!
//! `cure_asn1` is a Rust library designed for parsing [RPKI](https://www.rfc-editor.org/rfc/rfc6480)
//! objects encoded in ASN.1 format, as well as handling [RRDP (RPKI Repository Delta Protocol)]
//! objects. The library is build for efficiency and flexibility: It does not enforce any structure
//! or validation checks. It will parse any well-formated DER/BER encoded object.
//!
//! [RRDP (RPKI Repository Delta Protocol)]: https://www.rfc-editor.org/rfc/rfc8182

#![allow(dead_code)]

use crate::rpki::rpki::ObjectType;
use crate::tree_parser::Tree;

pub mod asn1_parser;
pub mod labeling;
pub mod mutator;
pub mod rpki;
pub mod tree_parser;
#[cfg(feature = "research")]
pub mod research;
pub mod tree_paths;
pub mod labels;

/// Parse DER-encoded Data into an Abstract Syntax Tree
pub fn parse_tree(data: &Vec<u8>, typ: &str) -> Option<Tree> {
    let tree_obj_typ = ObjectType::from_string(typ).into();
    match asn1_parser::parse_asn1_object_slim(data) {
        Ok(root) => Some(Tree::generate_tree(root, tree_obj_typ)),
        Err(e) => {
            eprintln!("Error during parsing: {}", e);
            None
        }
    }
}
