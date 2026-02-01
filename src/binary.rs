use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;

use crate::record::OwnedRecord;

const MAGIC: &[u8; 4] = b"ULP\x01";
const VERSION: u32 = 1;

#[derive(Error, Debug)]
pub enum BinaryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid magic bytes")]
    InvalidMagic,
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("Invalid record: field too large")]
    FieldTooLarge,
    #[error("Unexpected end of file")]
    UnexpectedEof,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Flags(u32);

impl Flags {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn compressed(&self) -> bool {
        self.0 & 1 != 0
    }

    pub fn set_compressed(&mut self, compressed: bool) {
        if compressed {
            self.0 |= 1;
        } else {
            self.0 &= !1;
        }
    }
}

#[derive(Debug)]
pub struct Header {
    pub version: u32,
    pub record_count: u32,
    pub flags: Flags,
}

impl Header {
    pub fn new(record_count: u32) -> Self {
        Self {
            version: VERSION,
            record_count,
            flags: Flags::new(),
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), BinaryError> {
        writer.write_all(MAGIC)?;
        writer.write_u32::<LittleEndian>(self.version)?;
        writer.write_u32::<LittleEndian>(self.record_count)?;
        writer.write_u32::<LittleEndian>(self.flags.0)?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, BinaryError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(BinaryError::InvalidMagic);
        }

        let version = reader.read_u32::<LittleEndian>()?;
        if version != VERSION {
            return Err(BinaryError::UnsupportedVersion(version));
        }

        let record_count = reader.read_u32::<LittleEndian>()?;
        let flags = Flags(reader.read_u32::<LittleEndian>()?);

        Ok(Self {
            version,
            record_count,
            flags,
        })
    }
}

pub struct BinaryWriter<W> {
    writer: W,
    count: u32,
}

impl<W: Write> BinaryWriter<W> {
    pub fn new(mut writer: W, estimated_count: u32) -> Result<Self, BinaryError> {
        let header = Header::new(estimated_count);
        header.write(&mut writer)?;
        Ok(Self { writer, count: 0 })
    }

    pub fn write_record(&mut self, record: &OwnedRecord) -> Result<(), BinaryError> {
        if record.url.len() > u16::MAX as usize {
            return Err(BinaryError::FieldTooLarge);
        }
        if record.username.len() > u16::MAX as usize {
            return Err(BinaryError::FieldTooLarge);
        }
        if record.password.len() > u16::MAX as usize {
            return Err(BinaryError::FieldTooLarge);
        }

        self.writer.write_u32::<LittleEndian>(record.line_num)?;

        self.writer.write_u16::<LittleEndian>(record.url.len() as u16)?;
        self.writer.write_all(&record.url)?;

        self.writer.write_u16::<LittleEndian>(record.username.len() as u16)?;
        self.writer.write_all(&record.username)?;

        self.writer.write_u16::<LittleEndian>(record.password.len() as u16)?;
        self.writer.write_all(&record.password)?;

        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn finish(self) -> W {
        self.writer
    }
}

pub struct BinaryReader<R> {
    reader: R,
    header: Header,
    records_read: u32,
}

impl<R: Read> BinaryReader<R> {
    pub fn new(mut reader: R) -> Result<Self, BinaryError> {
        let header = Header::read(&mut reader)?;
        Ok(Self {
            reader,
            header,
            records_read: 0,
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn record_count(&self) -> u32 {
        self.header.record_count
    }

    pub fn read_record(&mut self) -> Result<Option<OwnedRecord>, BinaryError> {
        if self.records_read >= self.header.record_count {
            return Ok(None);
        }

        let line_num = match self.reader.read_u32::<LittleEndian>() {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let url = self.read_field()?;
        let username = self.read_field()?;
        let password = self.read_field()?;

        self.records_read += 1;

        Ok(Some(OwnedRecord {
            line_num,
            url,
            username,
            password,
        }))
    }

    fn read_field(&mut self) -> Result<Box<[u8]>, BinaryError> {
        let len = self.reader.read_u16::<LittleEndian>()? as usize;
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        Ok(buf.into_boxed_slice())
    }
}

impl<R: Read> Iterator for BinaryReader<R> {
    type Item = Result<OwnedRecord, BinaryError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_record() -> OwnedRecord {
        OwnedRecord {
            line_num: 42,
            url: b"https://example.com/login".to_vec().into_boxed_slice(),
            username: b"testuser".to_vec().into_boxed_slice(),
            password: b"secret123".to_vec().into_boxed_slice(),
        }
    }

    #[test]
    fn test_header_roundtrip() {
        let mut buf = Vec::new();
        let header = Header::new(100);
        header.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let read_header = Header::read(&mut cursor).unwrap();

        assert_eq!(read_header.version, VERSION);
        assert_eq!(read_header.record_count, 100);
    }

    #[test]
    fn test_record_roundtrip() {
        let record = sample_record();
        let mut buf = Vec::new();

        {
            let mut writer = BinaryWriter::new(&mut buf, 1).unwrap();
            writer.write_record(&record).unwrap();
        }

        let cursor = Cursor::new(&buf);
        let mut reader = BinaryReader::new(cursor).unwrap();
        let read_record = reader.read_record().unwrap().unwrap();

        assert_eq!(read_record.line_num, record.line_num);
        assert_eq!(&*read_record.url, &*record.url);
        assert_eq!(&*read_record.username, &*record.username);
        assert_eq!(&*read_record.password, &*record.password);
    }

    #[test]
    fn test_multiple_records() {
        let records = vec![
            OwnedRecord {
                line_num: 1,
                url: b"https://a.com".to_vec().into_boxed_slice(),
                username: b"u1".to_vec().into_boxed_slice(),
                password: b"p1".to_vec().into_boxed_slice(),
            },
            OwnedRecord {
                line_num: 2,
                url: b"https://b.com".to_vec().into_boxed_slice(),
                username: b"u2".to_vec().into_boxed_slice(),
                password: b"p2".to_vec().into_boxed_slice(),
            },
        ];

        let mut buf = Vec::new();
        {
            let mut writer = BinaryWriter::new(&mut buf, 2).unwrap();
            for r in &records {
                writer.write_record(r).unwrap();
            }
        }

        let cursor = Cursor::new(&buf);
        let reader = BinaryReader::new(cursor).unwrap();
        let read_records: Vec<_> = reader.filter_map(Result::ok).collect();

        assert_eq!(read_records.len(), 2);
        assert_eq!(&*read_records[0].url, b"https://a.com");
        assert_eq!(&*read_records[1].url, b"https://b.com");
    }

    #[test]
    fn test_invalid_magic() {
        let buf = b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let cursor = Cursor::new(&buf[..]);
        let result = BinaryReader::new(cursor);
        assert!(matches!(result, Err(BinaryError::InvalidMagic)));
    }

    #[test]
    fn test_flags() {
        let mut flags = Flags::new();
        assert!(!flags.compressed());

        flags.set_compressed(true);
        assert!(flags.compressed());

        flags.set_compressed(false);
        assert!(!flags.compressed());
    }
}
