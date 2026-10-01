//! Demo: parse an RPKI object file (DER), show structure stats, re-encode and verify.
use cure_asn1::rpki::rpki::{ObjectType, RpkiObject};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: parse_demo <file> <type: roa|cer|mft|crl|asa|gbr|notification|snapshot|delta>");
        std::process::exit(1);
    }
    let data = std::fs::read(&args[1]).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {}", args[1], e);
        std::process::exit(1);
    });
    let typ = &args[2];
    let obj = RpkiObject::parse_as(&data, ObjectType::from_string(typ)).unwrap_or_else(|| {
        eprintln!("failed to parse {} as {}", args[1], typ);
        std::process::exit(1);
    });

    println!("file            : {}", args[1]);
    println!("object type     : {:?}", obj.typ);
    println!("input size      : {} bytes", data.len());
    println!("tree nodes      : {}", obj.content.tokens.len());
    println!("tree labels     : {}", obj.content.labels.len());

    // Round-trip: encode the tree back to DER and compare with the input
    let reencoded = obj.content.encode();
    let ok = reencoded == data;
    println!("re-encoded size : {} bytes", reencoded.len());
    println!("round-trip      : {}", if ok { "OK (identical DER)" } else { "DIFFERS from input" });
}
