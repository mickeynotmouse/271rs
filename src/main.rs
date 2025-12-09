// src/main.rs
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

const SCM_DIR: &str = ".scm";
const COMMITS_DIR: &str = ".scm/commits";
const HEAD_FILE: &str = ".scm/HEAD";
const KEYS_DIR: &str = ".scm/keys";
const PRIVATE_KEY_FILE: &str = ".scm/keys/private.key";
const PUBLIC_KEY_FILE: &str = ".scm/keys/public.key";

#[derive(Serialize, Deserialize, Debug)]
struct CommitMeta {
    id: String,
    timestamp: String,
    message: String,
    files: BTreeMap<String, String>, // path -> sha256 hex
    commit_hash: String,             // sha256 hex of concatenated entries
    signature: Option<String>,       // hex(signature)
    public_key: Option<String>,      // hex(pubkey)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "init" => init_repo()?,
        "commit" => {
            let message = if args.len() >= 3 { args[2..].join(" ") } else { "auto".into() };
            commit(&message)?
        }
        "revert" => revert()?,
        "log" => show_log()?,
        "head" => show_head()?,
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Simple SCM");
    println!("Usage:");
    println!("  scm init                 Initialize .scm in current directory");
    println!("  scm commit [message]     Commit current working tree (message optional)");
    println!("  scm revert               Revert to previous commit (verifies integrity & signature)");
    println!("  scm log                  Show commit history");
    println!("  scm head                 Show current HEAD");
}

fn init_repo() -> anyhow::Result<()> {
    if Path::new(SCM_DIR).exists() {
        println!(".scm already exists");
    } else {
        fs::create_dir(SCM_DIR)?;
        fs::create_dir(COMMITS_DIR)?;
        println!("Created {}", SCM_DIR);
    }

    if !Path::new(HEAD_FILE).exists() {
        fs::write(HEAD_FILE, "000000")?;
    }

    if !Path::new(KEYS_DIR).exists() {
        fs::create_dir_all(KEYS_DIR)?;
    }

    if !Path::new(PRIVATE_KEY_FILE).exists() || !Path::new(PUBLIC_KEY_FILE).exists() {
        println!("Generating Ed25519 keypair (stored in .scm/keys/) ...");
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);
        fs::write(PRIVATE_KEY_FILE, hex::encode(keypair.to_bytes()))?;
        fs::write(PUBLIC_KEY_FILE, hex::encode(keypair.public.to_bytes()))?;
        println!("Keypair generated.");
    } else {
        println!("Keys already available in .scm/keys/");
    }

    Ok(())
}

fn read_head() -> anyhow::Result<u64> {
    let s = fs::read_to_string(HEAD_FILE)?;
    let s_trim = s.trim();
    let n = s_trim.parse::<u64>().unwrap_or(0);
    Ok(n)
}

fn write_head(n: u64) -> anyhow::Result<()> {
    fs::write(HEAD_FILE, format!("{:06}", n))?;
    Ok(())
}

fn next_commit_id() -> anyhow::Result<u64> {
    let head = read_head()?;
    Ok(head + 1)
}

fn commit(message: &str) -> anyhow::Result<()> {
    if !Path::new(SCM_DIR).exists() {
        println!(".scm not found: running init...");
        init_repo()?;
    }

    let id_n = next_commit_id()?;
    let id = format!("{:06}", id_n);
    let commit_path = Path::new(COMMITS_DIR).join(&id);
    let files_path = commit_path.join("files");

    fs::create_dir_all(&files_path)?;

    let cwd = env::current_dir()?;
    for entry in WalkDir::new(&cwd).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.components().any(|c| c.as_os_str() == SCM_DIR) {
            continue;
        }
        if path.is_file() {
            let rel = path.strip_prefix(&cwd).unwrap();
            let dest = files_path.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(path, &dest)?;
        }
    }

    let mut file_hashes = BTreeMap::new();
    for entry in WalkDir::new(&files_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let rel = path.strip_prefix(&files_path).unwrap().to_string_lossy().to_string();
            let h = sha256_of_file(path)?;
            file_hashes.insert(rel, h);
        }
    }

    let mut hasher = Sha256::new();
    for (path, hash) in &file_hashes {
        let line = format!("{}:{}\n", path, hash);
        hasher.update(line.as_bytes());
    }
    let commit_hash = hex::encode(hasher.finalize());

    let keypair = load_or_generate_keypair()?;
    let signature = keypair.sign(commit_hash.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());
    let pubkey_hex = hex::encode(keypair.public.to_bytes());

    let meta = CommitMeta {
        id: id.clone(),
        timestamp: timestamp_now(),
        message: message.to_string(),
        files: file_hashes,
        commit_hash: commit_hash.clone(),
        signature: Some(signature_hex),
        public_key: Some(pubkey_hex),
    };

    let meta_json = serde_json::to_string_pretty(&meta)?;
    fs::write(commit_path.join("meta.json"), meta_json)?;

    write_head(id_n)?;

    println!("Committed {}", id);
    Ok(())
}

fn sha256_of_file(p: &Path) -> anyhow::Result<String> {
    let mut f = fs::File::open(p)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn load_or_generate_keypair() -> anyhow::Result<Keypair> {
    if Path::new(PRIVATE_KEY_FILE).exists() && Path::new(PUBLIC_KEY_FILE).exists() {
        let priv_hex = fs::read_to_string(PRIVATE_KEY_FILE)?;
        let priv_bytes = hex::decode(priv_hex.trim())?;
        if priv_bytes.len() != 64 {
            anyhow::bail!("private key length unexpected");
        }
        let kp = Keypair::from_bytes(&priv_bytes)?;
        Ok(kp)
    } else {
        let mut csprng = OsRng {};
        let kp = Keypair::generate(&mut csprng);
        fs::write(PRIVATE_KEY_FILE, hex::encode(kp.to_bytes()))?;
        fs::write(PUBLIC_KEY_FILE, hex::encode(kp.public.to_bytes()))?;
        Ok(kp)
    }
}

fn timestamp_now() -> String {
    let now = SystemTime::now();
    let datetime: chrono::DateTime<chrono::Utc> = now.into();
    datetime.to_rfc3339()
}

fn revert() -> anyhow::Result<()> {
    if !Path::new(SCM_DIR).exists() {
        anyhow::bail!(".scm not initialized (run `scm init`)");
    }

    let head = read_head()?;
    if head == 0 {
        anyhow::bail!("No commits to revert");
    }
    let current_id = format!("{:06}", head);
    if head == 1 {
        anyhow::bail!("No previous commit to revert to (only one commit exists)");
    }
    let previous_id_n = head - 1;
    let previous_id = format!("{:06}", previous_id_n);

    let prev_commit_path = Path::new(COMMITS_DIR).join(&previous_id);
    let prev_meta_path = prev_commit_path.join("meta.json");
    if !prev_meta_path.exists() {
        anyhow::bail!("Previous commit meta not found: {:?}", prev_meta_path);
    }

    let meta_text = fs::read_to_string(&prev_meta_path)?;
    let meta: CommitMeta = serde_json::from_str(&meta_text)?;

    let files_dir = prev_commit_path.join("files");
    for (rel, saved_hash) in &meta.files {
        let path = files_dir.join(rel);
        if !path.exists() {
            anyhow::bail!("File missing in commit snapshot: {}", rel);
        }
        let h = sha256_of_file(&path)?;
        if &h != saved_hash {
            anyhow::bail!("Integrity check failed for {}: expected {}, got {}", rel, saved_hash, h);
        }
    }

    if let (Some(sig_hex), Some(pub_hex)) = (meta.signature.as_ref(), meta.public_key.as_ref()) {
        let sig_bytes = hex::decode(sig_hex)?;
        let pub_bytes = hex::decode(pub_hex)?;
        if sig_bytes.len() != 64 || pub_bytes.len() != 32 {
            anyhow::bail!("Signature/public key length mismatch");
        }
        let signature = Signature::from_bytes(&sig_bytes)?;
        let public = PublicKey::from_bytes(&pub_bytes)?;
        public.verify(meta.commit_hash.as_bytes(), &signature)?;
    } else {
        anyhow::bail!("No signature/public key found on previous commit; refusing to revert");
    }

    let cwd = env::current_dir()?;
    for entry in WalkDir::new(&files_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let rel = path.strip_prefix(&files_dir).unwrap();
            let dest = cwd.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(path, &dest)?;
        }
    }

    write_head(previous_id_n)?;

    let current_commit_path = Path::new(COMMITS_DIR).join(&current_id);
    if current_commit_path.exists() {
        fs::remove_dir_all(current_commit_path)?;
    }

    println!("Reverted to commit {}", previous_id);
    Ok(())
}

fn show_log() -> anyhow::Result<()> {
    if !Path::new(COMMITS_DIR).exists() {
        println!("No commits yet.");
        return Ok(());
    }
    let mut commits: Vec<_> = fs::read_dir(COMMITS_DIR)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .collect();
    commits.sort_by_key(|e| e.file_name());

    for entry in commits {
        let meta_path = entry.path().join("meta.json");
        if meta_path.exists() {
            let meta_text = fs::read_to_string(meta_path)?;
            let meta: CommitMeta = serde_json::from_str(&meta_text)?;
            println!("commit {}", meta.id);
            println!("  time: {}", meta.timestamp);
            println!("  msg: {}", meta.message);
            println!("  files: {} entries", meta.files.len());
            println!("  hash: {}", meta.commit_hash);
            println!();
        }
    }
    Ok(())
}

fn show_head() -> anyhow::Result<()> {
    if !Path::new(HEAD_FILE).exists() {
        println!("No HEAD (initialize with `scm init`)");
        return Ok(());
    }
    let head = fs::read_to_string(HEAD_FILE)?;
    println!("HEAD: {}", head.trim());
    Ok(())
}

