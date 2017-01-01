#[derive(Debug, Clone)]
pub struct TCPSegment {
    pub data: Vec<u8>,
    pub sequence_number: u32,
}

impl TCPSegment {
    pub fn new(data: Vec<u8>, sequence_number: u32) -> TCPSegment {
        TCPSegment {
            data: data,
            sequence_number: sequence_number,
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_segment() {
        let test_length = 10;
        let data = vec![0u8; test_length];
        let sequence_number = 1;

        let segment = TCPSegment::new(data, sequence_number);

        assert_eq!(segment.sequence_number, sequence_number);
        assert_eq!(segment.len(), test_length);
    }
}
