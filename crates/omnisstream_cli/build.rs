fn main() {
    let Some(git_dir) = find_git_dir() else {
        println!("cargo:rustc-env=OMNISSTREAM_GIT_COMMIT=unknown");
        return;
    };

    let common_git_dir = find_common_git_dir(&git_dir);
    let commit =
        read_git_commit(&git_dir, &common_git_dir).unwrap_or_else(|| "unknown".to_string());

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

fn find_common_git_dir(git_dir: &Path) -> PathBuf {
    let commondir_path = git_dir.join("commondir");
    println!("cargo:rerun-if-changed={}", commondir_path.display());

    let Some(common_dir) = std::fs::read_to_string(&commondir_path)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
    else {
        return git_dir.to_path_buf();
    };

    let common_dir = PathBuf::from(common_dir);
    if common_dir.is_absolute() {
        common_dir
    } else {
        git_dir.join(common_dir)
    }
}

fn read_git_commit(git_dir: &Path, common_git_dir: &Path) -> Option<String> {
    let head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());

    let head = std::fs::read_to_string(&head_path).ok()?;
    let head = head.trim();

    if let Some(r) = head.strip_prefix("ref:") {
        let rel = r.trim();

        for ref_path in candidate_git_paths(git_dir, common_git_dir, rel) {
            if ref_path.is_file() {
                println!("cargo:rerun-if-changed={}", ref_path.display());
                let commit = std::fs::read_to_string(ref_path).ok()?;
                return Some(commit.trim().to_string());
            }
        }

        for packed_path in candidate_git_paths(git_dir, common_git_dir, "packed-refs") {
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
        }

        None
    } else {
        // Detached HEAD: HEAD contains the commit hash.
        Some(head.to_string())
    }
}

fn candidate_git_paths(git_dir: &Path, common_git_dir: &Path, rel: &str) -> Vec<PathBuf> {
    let mut paths = vec![git_dir.join(rel)];
    if common_git_dir != git_dir {
        paths.push(common_git_dir.join(rel));
    }
    paths
}
