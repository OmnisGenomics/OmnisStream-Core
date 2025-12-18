use std::fs::File;
use std::io;
use std::sync::Arc;

use omnisstream_backend_api::IngestBackend;

#[derive(Clone)]
pub(crate) struct PreadBackend {
    file: Arc<File>,
}

impl PreadBackend {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file: Arc::new(file),
        }
    }
}

impl IngestBackend for PreadBackend {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut read = 0_usize;
        while read < buf.len() {
            let n = read_at(
                &self.file,
                &mut buf[read..],
                offset.saturating_add(read as u64),
            )?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }
            read += n;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt as _;
    file.read_at(buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt as _;
    file.seek_read(buf, offset)
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct MemBackend {
    bytes: Arc<Vec<u8>>,
}

#[cfg(test)]
impl MemBackend {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(bytes),
        }
    }
}

#[cfg(test)]
impl IngestBackend for MemBackend {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start: usize = offset
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "offset out of range"))?;
        let end = start.saturating_add(buf.len());
        if end > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }

        buf.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
}
