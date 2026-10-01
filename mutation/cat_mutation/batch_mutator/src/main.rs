//! Batch structure-aware mutation of an RPKI repository using cure_asn1.
//!
//! Adapted from cure_asn1's examples/repo_mutate_demo.rs (copy; original untouched).
//!
//! Usage:
//!   batch_mutator mutate-repo <repo_root> [--rounds N] [--types cer,mft,roa,crl,asa,gbr]
//!                    [--num-objects K|all] [--seed S] [--include-ta] [--dry] [--meta PATH] [--state-dir DIR]
//!
//! Walks <repo_root>, picks objects of the requested extensions (skipping key/,
//! tal/ and the TAL-referenced TA cert unless --include-ta), applies
//! mutator::mutate_tree with N rounds per object and overwrites the file.
//! Prints one JSON line per mutated object and a final summary object.

use cure_asn1::mutator::mutate_tree;
use cure_asn1::parse_tree;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Deterministic xorshift RNG for object selection (no external rand dep).
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

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

/// Collect candidate objects: relpath, abs path, type. Skips key/ and tal/
/// directories; the TAL-referenced root cert (ca_certificate.cer at the repo
/// root) is only included with --include-ta.
fn collect_objects(
    repo: &Path,
    types: &BTreeSet<&'static str>,
    include_ta: bool,
) -> Vec<(String, PathBuf, &'static str)> {
    let mut out = Vec::new();
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
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // key/, tal/: not published objects; rsync/, my_repo/: RP caches
                if matches!(name, "key" | "tal" | "rsync" | "my_repo") {
                    continue;
                }
                stack.push(p);
            } else if let Some(typ) = obj_type_of(&p) {
                if !types.contains(typ) {
                    continue;
                }
                let rel = p.strip_prefix(repo).unwrap().to_string_lossy().to_string();
                // TAL references <root>/ca_certificate.cer by pubkey; mutating
                // it breaks the TAL match and kills the whole repo at stage 0.
                if rel == "ca_certificate.cer" && !include_ta {
                    continue;
                }
                out.push((rel, p, typ));
            }
        }
    }
    out
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "mutate-repo" {
        eprintln!(
            "usage: {} mutate-repo <repo_root> [--rounds N] [--types cer,mft] \
             [--num-objects K|all] [--seed S] [--include-ta] [--dry] [--meta PATH] [--state-dir DIR]",
            args[0]
        );
        std::process::exit(1);
    }
    let repo = PathBuf::from(&args[2]);

    let flag = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };
    let rounds: usize = flag("--rounds").and_then(|v| v.parse().ok()).unwrap_or(1);
    // separate budget for the TAL-referenced TA cert (nofix parity with
    // test_noDep: TA gets 3 field targets, sub-CAs 7)
    let ta_rounds: usize = flag("--ta-rounds").and_then(|v| v.parse().ok()).unwrap_or(rounds);
    let types: BTreeSet<&'static str> = flag("--types")
        .unwrap_or_else(|| "cer".to_string())
        .split(',')
        .filter_map(|t| obj_type_of(Path::new(&format!("x.{}", t.trim()))))
        .collect();
    let num_objects = flag("--num-objects").unwrap_or_else(|| "all".to_string());
    let seed: u64 = flag("--seed").and_then(|v| v.parse().ok()).unwrap_or(0x5eed_cafe);
    let include_ta = args.iter().any(|a| a == "--include-ta");
    let dry = args.iter().any(|a| a == "--dry");
    let meta_path = flag("--meta");
    let backup_dir = flag("--backup-dir");
    let state_dir = flag("--state-dir");

    let mut objects = collect_objects(&repo, &types, include_ta);
    if num_objects != "all" {
        let k: usize = num_objects.parse().unwrap_or(objects.len());
        if k < objects.len() {
            // deterministic subsample: partial Fisher-Yates with seeded rng
            let mut rng = XorShift(seed | 1);
            for i in 0..k {
                let j = i + rng.below(objects.len() - i);
                objects.swap(i, j);
            }
            objects.truncate(k);
        }
    }

    let mut mutated = 0usize;
    let mut parse_fail = 0usize;
    let mut panic_skip = 0usize;
    let mut ta_panicked = false;
    let mut encode_equal = 0usize;
    let mut meta_lines: Vec<String> = Vec::new();

    for (rel, path, typ) in &objects {
        let data = std::fs::read(path).unwrap_or_default();
        let is_ta = rel == "ca_certificate.cer";
        // pristine copy for the differential flag protocol (repair arm):
        // fields that differ from the backup are "intentionally mutated"
        if let Some(bd) = &backup_dir {
            let bpath = std::path::Path::new(bd).join(rel);
            if let Some(parent) = bpath.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&bpath, &data);
        }
        let n_rounds = if is_ta { ta_rounds } else { rounds };

        // cure_asn1's labeling can panic on some certs (library bug); catch it
        // per object so one bad cert skips instead of killing the whole repo
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut tree = match parse_tree(&data, typ) {
                Some(t) => t,
                None => return (None, data.clone(), Vec::new(), false),
            };
            mutate_tree(&mut tree, n_rounds);
            let mut state_tree = tree.clone();
            // serde_json cannot represent HashMap<Label, usize> as JSON object
            // keys. Token.info preserves the labels needed by the repair stage.
            state_tree.labels.clear();
            let state_json = serde_json::to_vec_pretty(&state_tree).ok();
            let der = tree.encode();
            let reparsable = parse_tree(&der, typ).is_some();
            let mutations: Vec<String> = tree
                .mutations
                .iter()
                .map(|m| m.get_mutation_string())
                .collect();
            (Some(state_json), der, mutations, reparsable)
        }));

        let (tree, der, mutations, reparsable) = match outcome {
            Ok((Some(state_json), der, mutations, reparsable)) => (state_json, der, mutations, reparsable),
            Ok((None, ..)) => {
                parse_fail += 1;
                let line = format!(
                    "{{\"file\": \"{}\", \"type\": \"{}\", \"error\": \"parse_failed\"}}",
                    json_escape(rel),
                    typ
                );
                println!("{}", line);
                meta_lines.push(line);
                continue;
            }
            Err(_) => {
                panic_skip += 1;
                if is_ta {
                    ta_panicked = true;
                }
                let line = format!(
                    "{{\"file\": \"{}\", \"type\": \"{}\", \"error\": \"library_panic_skipped\"}}",
                    json_escape(rel),
                    typ
                );
                println!("{}", line);
                meta_lines.push(line);
                continue;
            }
        };
        if !dry {
            std::fs::write(path, &der).unwrap_or_else(|e| {
                eprintln!("cannot write {}: {}", path.display(), e);
                std::process::exit(1);
            });
            if let (Some(sd), Some(state_json)) = (&state_dir, &tree) {
                let spath = std::path::Path::new(sd).join(format!("{}.tree.json", rel));
                if let Some(parent) = spath.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&spath, state_json);
            }
        }
        if der == data {
            encode_equal += 1;
        }
        mutated += 1;
        let state_rel = if state_dir.is_some() { format!("{}{}", rel, ".tree.json") } else { String::new() };
        let line = format!(
            "{{\"file\": \"{}\", \"type\": \"{}\", \"rounds\": {}, \"old_size\": {}, \"new_size\": {}, \"reparsable\": {}, \"state\": \"{}\", \"mutations\": [{}]}}",
            json_escape(rel),
            typ,
            n_rounds,
            data.len(),
            der.len(),
            reparsable,
            json_escape(&state_rel),
            mutations
                .iter()
                .map(|m| format!("\"{}\"", json_escape(m)))
                .collect::<Vec<_>>()
                .join(",")
        );
        println!("{}", line);
        meta_lines.push(line);
    }

    let summary = format!(
        "{{\"summary\": {{\"candidates\": {}, \"mutated\": {}, \"parse_fail\": {}, \"panic_skip\": {}, \"ta_panicked\": {}, \"encode_equal\": {}, \"rounds\": {}, \"ta_rounds\": {}, \"types\": \"{}\", \"include_ta\": {}, \"seed\": {}}}}}",
        objects.len(),
        mutated,
        parse_fail,
        panic_skip,
        ta_panicked,
        encode_equal,
        rounds,
        ta_rounds,
        flag("--types").unwrap_or_else(|| "cer".to_string()),
        include_ta,
        seed
    );
    println!("{}", summary);
    if let Some(mp) = meta_path {
        meta_lines.push(summary);
        std::fs::write(&mp, meta_lines.join("\n") + "\n")
            .unwrap_or_else(|e| eprintln!("cannot write meta {}: {}", mp, e));
    }
}
