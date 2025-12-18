use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn fsync_dir(path: &Path) -> io::Result<()> {
    let dir = File::open(path)?;
    dir.sync_all()
}

pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    std::fs::create_dir_all(parent)?;

    let tmp_path = tmp_path_for_final(path);
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    // Ensure the temp dir entry is durable before rename on platforms that require it.
    fsync_dir(parent)?;

    std::fs::rename(&tmp_path, path)?;

    // Ensure the rename is durable.
    fsync_dir(parent)?;
    Ok(())
}

pub fn atomic_write_string(path: &Path, s: &str) -> io::Result<()> {
    atomic_write_bytes(path, s.as_bytes())
}

pub fn tmp_path_for_final(final_path: &Path) -> PathBuf {
    let mut name = final_path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    final_path.with_file_name(name)
}

pub fn read_to_string_if_exists(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn ensure_dir(path: &Path) -> io::Result<PathBuf> {
    std::fs::create_dir_all(path)?;
    Ok(path.to_path_buf())
}
