use std::io::{self, Read};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Crc32c(u32);

impl Crc32c {
    pub(crate) fn from_u32(value: u32) -> Self {
        Self(value)
    }

    pub fn value(self) -> u32 {
        self.0
    }

    /// Digest bytes in big-endian (network) order.
    pub fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn to_be_hex(self) -> String {
        hex::encode(self.to_be_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Blake3Digest([u8; 32]);

impl Blake3Digest {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashSummary {
    pub len: u64,
    pub crc32c: Crc32c,
    pub blake3_256: Blake3Digest,
}

pub fn crc32c_bytes(bytes: &[u8]) -> Crc32c {
    Crc32c(crc32c::crc32c(bytes))
}

pub fn blake3_256_bytes(bytes: &[u8]) -> Blake3Digest {
    Blake3Digest(*blake3::hash(bytes).as_bytes())
}

/// Computes CRC32C + BLAKE3-256 in a single streaming pass.
pub fn hash_reader(reader: &mut impl Read) -> io::Result<HashSummary> {
    let mut crc = 0_u32;
    let mut hasher = blake3::Hasher::new();

    let mut buf = [0_u8; 64 * 1024];
    let mut len = 0_u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        len += n as u64;
        crc = crc32c::crc32c_append(crc, &buf[..n]);
        hasher.update(&buf[..n]);
    }

    Ok(HashSummary {
        len,
        crc32c: Crc32c(crc),
        blake3_256: Blake3Digest(*hasher.finalize().as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    #[derive(Debug)]
    struct ExpectedLine {
        rel_path: String,
        size: u64,
        crc32c_be: [u8; 4],
        blake3_256: [u8; 32],
    }

    fn spec_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/omnisstream-spec")
    }

    fn parse_expected_line(line: &str) -> Option<ExpectedLine> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        let mut fields = line.split('\t');
        let rel_path = fields.next()?.to_string();

        let mut size = None;
        let mut crc32c_be = None;
        let mut blake3_256 = None;

        for field in fields {
            if let Some(v) = field.strip_prefix("size=") {
                size = Some(v.parse::<u64>().ok()?);
            } else if let Some(v) = field.strip_prefix("crc32c_be_hex=") {
                let bytes = hex::decode(v).ok()?;
                if bytes.len() != 4 {
                    return None;
                }
                let mut out = [0_u8; 4];
                out.copy_from_slice(&bytes);
                crc32c_be = Some(out);
            } else if let Some(v) = field.strip_prefix("blake3_256_hex=") {
                let bytes = hex::decode(v).ok()?;
                if bytes.len() != 32 {
                    return None;
                }
                let mut out = [0_u8; 32];
                out.copy_from_slice(&bytes);
                blake3_256 = Some(out);
            }
        }

        Some(ExpectedLine {
            rel_path,
            size: size?,
            crc32c_be: crc32c_be?,
            blake3_256: blake3_256?,
        })
    }

    fn verify_vector(vector_dir: &str) {
        let vector_path = spec_root().join("test-vectors").join(vector_dir);
        let expected_txt =
            std::fs::read_to_string(vector_path.join("EXPECTED.txt")).expect("read EXPECTED.txt");

        for line in expected_txt.lines() {
            let Some(expected) = parse_expected_line(line) else {
                continue;
            };

            let part_path = vector_path.join(&expected.rel_path);
            let mut f = std::fs::File::open(&part_path).expect("open part");
            let got = hash_reader(&mut f).expect("hash");

            assert_eq!(
                got.len,
                expected.size,
                "size mismatch for {}",
                part_path.display()
            );
            assert_eq!(
                got.crc32c.to_be_bytes(),
                expected.crc32c_be,
                "crc32c mismatch for {}",
                part_path.display()
            );
            assert_eq!(
                got.blake3_256.as_bytes(),
                &expected.blake3_256,
                "blake3 mismatch for {}",
                part_path.display()
            );
        }
    }

    #[test]
    fn digests_match_spec_vectors_minimal() {
        verify_vector("vector-minimal");
    }

    #[test]
    fn digests_match_spec_vectors_compressed() {
        verify_vector("vector-compressed");
    }

    #[test]
    fn crc32c_big_endian_hex_matches() {
        let got = crc32c_bytes(b"hello");
        let u32_be = u32::from_be_bytes(got.to_be_bytes());
        assert_eq!(u32_be, got.value());
        assert_eq!(got.to_be_hex().len(), 8);
    }

    #[test]
    fn blake3_hex_matches() {
        let got = blake3_256_bytes(b"hello");
        assert_eq!(got.to_hex().len(), 64);
    }

    #[test]
    fn hash_reader_is_streaming() {
        struct CountingReader<'a> {
            inner: &'a [u8],
            reads: usize,
        }

        impl Read for CountingReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                let n = std::cmp::min(buf.len(), self.inner.len());
                buf[..n].copy_from_slice(&self.inner[..n]);
                self.inner = &self.inner[n..];
                Ok(n)
            }
        }

        let data = vec![0_u8; 256 * 1024];
        let mut r = CountingReader {
            inner: &data,
            reads: 0,
        };
        let out = hash_reader(&mut r).unwrap();
        assert_eq!(out.len, data.len() as u64);
        assert!(r.reads > 1);
    }

    #[test]
    fn hash_reader_matches_bytes_functions() {
        let data = b"abcdefg1234567";
        let mut r: &mut dyn Read = &mut &data[..];
        let out = hash_reader(&mut r).unwrap();
        assert_eq!(out.crc32c, crc32c_bytes(data));
        assert_eq!(out.blake3_256, blake3_256_bytes(data));
    }

    #[test]
    fn to_be_hex_is_lowercase_stable() {
        let got = crc32c_bytes(b"hello").to_be_hex();
        assert!(got
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn to_hex_is_lowercase_stable() {
        let got = blake3_256_bytes(b"hello").to_hex();
        assert!(got
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn verify_vector_paths_are_relative() {
        let v = spec_root().join("test-vectors/vector-minimal/EXPECTED.txt");
        let expected_txt = std::fs::read_to_string(&v).unwrap();
        for line in expected_txt.lines() {
            let Some(expected) = parse_expected_line(line) else {
                continue;
            };
            assert!(
                Path::new(&expected.rel_path).is_relative(),
                "expected rel path to be relative"
            );
        }
    }
}
