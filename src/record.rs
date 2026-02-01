#[derive(Debug, Clone)]
pub struct Record<'a> {
    pub line_num: u32,
    pub url: &'a [u8],
    pub username: &'a [u8],
    pub password: &'a [u8],
}

impl<'a> Record<'a> {
    pub fn to_owned(&self) -> OwnedRecord {
        OwnedRecord {
            line_num: self.line_num,
            url: self.url.to_vec().into_boxed_slice(),
            username: self.username.to_vec().into_boxed_slice(),
            password: self.password.to_vec().into_boxed_slice(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OwnedRecord {
    pub line_num: u32,
    pub url: Box<[u8]>,
    pub username: Box<[u8]>,
    pub password: Box<[u8]>,
}

impl OwnedRecord {
    pub fn as_ref(&self) -> Record<'_> {
        Record {
            line_num: self.line_num,
            url: &self.url,
            username: &self.username,
            password: &self.password,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_to_owned() {
        let url = b"https://example.com";
        let username = b"user";
        let password = b"pass";

        let record = Record {
            line_num: 42,
            url: url,
            username: username,
            password: password,
        };

        let owned = record.to_owned();
        assert_eq!(owned.line_num, 42);
        assert_eq!(&*owned.url, url);
        assert_eq!(&*owned.username, username);
        assert_eq!(&*owned.password, password);
    }

    #[test]
    fn test_owned_record_as_ref() {
        let owned = OwnedRecord {
            line_num: 1,
            url: b"https://test.com".to_vec().into_boxed_slice(),
            username: b"admin".to_vec().into_boxed_slice(),
            password: b"secret".to_vec().into_boxed_slice(),
        };

        let borrowed = owned.as_ref();
        assert_eq!(borrowed.line_num, 1);
        assert_eq!(borrowed.url, b"https://test.com");
    }
}
