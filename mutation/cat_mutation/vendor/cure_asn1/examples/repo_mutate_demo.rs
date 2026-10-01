//! Demo: structure-aware mutation of RPKI repository objects using cure_asn1.
//!
//! Usage:
//!   repo_mutate_demo list   <repo_dir>
//!   repo_mutate_demo mutate <repo_dir> <relpath> <rounds> [--dry]
//!
//! `list`   prints one line per RPKI object: relpath<TAB>type<TAB>size<TAB>roundtrip
//! `mutate` parses the object into a cure_asn1 Tree, applies N rounds of
//!          mutator::mutate_tree, re-encodes to DER and overwrites the file
//!          (unless --dry). Prints a JSON summary of the applied mutations.
use cure_asn1::mutator::mutate_tree;
use cure_asn1::parse_tree;
use std::path::{Path, PathBuf};

fn obj_type_of(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("roa") => Some("roa"),
        Some("mft") => Some("mft"),
        Some("cer") => Some("cer"),
        Some("crl") => Some("crl"),
        Some("asa") => Some("asa"),
        Some("gbr") => Some("gbr"),
        _ => None,
    }
}

fn collect_objects(repo: &Path, out: &mut Vec<(PathBuf, &'static str, u64)>) {
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
            Err(_) => continue,
        };
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Some(typ) = obj_type_of(&p) {
                let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                out.push((p, typ, size));
            }
        }
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} list <repo_dir> | mutate <repo_dir> <relpath> <rounds> [--dry]",
            args[0]
        );
        std::process::exit(1);
    }
    let mode = args[1].as_str();
    let repo = PathBuf::from(&args[2]);

    match mode {
        "list" => {
            let mut objs = Vec::new();
            collect_objects(&repo, &mut objs);
            for (p, typ, size) in objs {
                let rel = p.strip_prefix(&repo).unwrap().to_string_lossy();
                let data = std::fs::read(&p).unwrap_or_default();
                let roundtrip = parse_tree(&data, typ)
                    .map(|t| t.encode() == data)
                    .unwrap_or(false);
                println!("{}\t{}\t{}\t{}", rel, typ, size, roundtrip);
            }
        }
        "mutate" => {
            if args.len() < 5 {
                eprintln!("mutate needs <relpath> <rounds>");
                std::process::exit(1);
            }
            let rel = &args[3];
            let rounds: usize = args[4].parse().unwrap_or_else(|_| {
                eprintln!("rounds must be a number");
                std::process::exit(1);
            });
            let dry = args.iter().any(|a| a == "--dry");
            let target = repo.join(rel);
            let typ = obj_type_of(&target).unwrap_or_else(|| {
                eprintln!("unsupported object type: {}", rel);
                std::process::exit(1);
            });

            let data = std::fs::read(&target).unwrap_or_else(|e| {
                eprintln!("cannot read {}: {}", target.display(), e);
                std::process::exit(1);
            });
            let mut tree = parse_tree(&data, typ).unwrap_or_else(|| {
                eprintln!("failed to parse {} as {}", rel, typ);
                std::process::exit(1);
            });

            mutate_tree(&mut tree, rounds);

            let der = tree.encode();
            // can cure_asn1 itself re-parse the mutated object?
            let reparsable = parse_tree(&der, typ).is_some();

            let mutations: Vec<String> = tree
                .mutations
                .iter()
                .map(|m| m.get_mutation_string())
                .collect();

            if !dry {
                std::fs::write(&target, &der).unwrap_or_else(|e| {
                    eprintln!("cannot write {}: {}", target.display(), e);
                    std::process::exit(1);
                });
            }
            println!(
                "{{\"file\": \"{}\", \"type\": \"{}\", \"rounds\": {}, \"old_size\": {}, \"new_size\": {}, \"reparsable\": {}, \"mutations\": [{}]}}",
                json_escape(rel),
                typ,
                rounds,
                data.len(),
                der.len(),
                reparsable,
                mutations
                    .iter()
                    .map(|m| format!("\"{}\"", json_escape(m)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        _ => {
            eprintln!("unknown mode {}", mode);
            std::process::exit(1);
        }
    }
}
