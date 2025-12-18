fn main() {
    let Some(git_dir) = find_git_dir() else {
        println!("cargo:rustc-env=OMNISSTREAM_GIT_COMMIT=unknown");
        return;
    };

    let commit = read_git_commit(&git_dir).unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=OMNISSTREAM_GIT_COMMIT={commit}");
}

use std::path::{Path, PathBuf};

fn find_git_dir() -> Option<PathBuf> {
    let start = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
    let mut dir = start.as_path();
    loop {
        let dot_git = dir.join(".git");
        if dot_git.is_dir() {
            return Some(dot_git);
        }
        if dot_git.is_file() {
            return read_gitdir_file(&dot_git);
        }
        dir = dir.parent()?;
    }
}

fn read_gitdir_file(dot_git_file: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(dot_git_file).ok()?;
    let line = text.lines().next()?.trim();
    let path = line.strip_prefix("gitdir:")?.trim();
    let gitdir = dot_git_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(path);
    Some(gitdir)
}

fn read_git_commit(git_dir: &Path) -> Option<String> {
    let head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());

    let head = std::fs::read_to_string(&head_path).ok()?;
    let head = head.trim();

    if let Some(r) = head.strip_prefix("ref:") {
        let rel = r.trim();

        let ref_path = git_dir.join(rel);
        if ref_path.is_file() {
            println!("cargo:rerun-if-changed={}", ref_path.display());
            let commit = std::fs::read_to_string(ref_path).ok()?;
            return Some(commit.trim().to_string());
        }

        let packed_path = git_dir.join("packed-refs");
        if packed_path.is_file() {
            println!("cargo:rerun-if-changed={}", packed_path.display());
            let packed = std::fs::read_to_string(packed_path).ok()?;
            for line in packed.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
                    continue;
                }
                let mut fields = line.split_whitespace();
                let Some(hash) = fields.next() else {
                    continue;
                };
                let Some(name) = fields.next() else {
                    continue;
                };
                if name == rel {
                    return Some(hash.to_string());
                }
            }
        }

        None
    } else {
        // Detached HEAD: HEAD contains the commit hash.
        Some(head.to_string())
    }
}
