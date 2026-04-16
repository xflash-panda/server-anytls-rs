pub const HEADER_SIZE: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Waste = 0,
    Syn = 1,
    Psh = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl TryFrom<u8> for Command {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Command::Waste),
            1 => Ok(Command::Syn),
            2 => Ok(Command::Psh),
            3 => Ok(Command::Fin),
            4 => Ok(Command::Settings),
            5 => Ok(Command::Alert),
            6 => Ok(Command::UpdatePaddingScheme),
            7 => Ok(Command::SynAck),
            8 => Ok(Command::HeartRequest),
            9 => Ok(Command::HeartResponse),
            10 => Ok(Command::ServerSettings),
            _ => Err(crate::error::Error::InvalidFrame(format!(
                "unknown command: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub command: Command,
    pub stream_id: u32,
    pub length: u16,
}

impl FrameHeader {
    pub fn encode(&self, buf: &mut [u8; HEADER_SIZE]) {
        buf[0] = self.command as u8;
        buf[1..5].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[5..7].copy_from_slice(&self.length.to_be_bytes());
    }

    pub fn decode(buf: &[u8; HEADER_SIZE]) -> Self {
        let command = Command::try_from(buf[0]).unwrap_or(Command::Waste);
        let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let length = u16::from_be_bytes([buf[5], buf[6]]);
        FrameHeader {
            command,
            stream_id,
            length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_values() {
        assert_eq!(Command::Waste as u8, 0);
        assert_eq!(Command::Syn as u8, 1);
        assert_eq!(Command::Psh as u8, 2);
        assert_eq!(Command::Fin as u8, 3);
        assert_eq!(Command::Settings as u8, 4);
        assert_eq!(Command::Alert as u8, 5);
        assert_eq!(Command::UpdatePaddingScheme as u8, 6);
        assert_eq!(Command::SynAck as u8, 7);
        assert_eq!(Command::HeartRequest as u8, 8);
        assert_eq!(Command::HeartResponse as u8, 9);
        assert_eq!(Command::ServerSettings as u8, 10);
    }

    #[test]
    fn test_command_from_u8() {
        assert_eq!(Command::try_from(0).unwrap(), Command::Waste);
        assert_eq!(Command::try_from(10).unwrap(), Command::ServerSettings);
        assert!(Command::try_from(11).is_err());
        assert!(Command::try_from(255).is_err());
    }

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let header = FrameHeader {
            command: Command::Psh,
            stream_id: 42,
            length: 1024,
        };
        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf);
        let decoded = FrameHeader::decode(&buf);
        assert_eq!(decoded.command, Command::Psh);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.length, 1024);
    }

    #[test]
    fn test_header_max_values() {
        let header = FrameHeader {
            command: Command::ServerSettings,
            stream_id: u32::MAX,
            length: u16::MAX,
        };
        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf);
        let decoded = FrameHeader::decode(&buf);
        assert_eq!(decoded.command, Command::ServerSettings);
        assert_eq!(decoded.stream_id, u32::MAX);
        assert_eq!(decoded.length, u16::MAX);
    }

    #[test]
    fn test_header_zero_values() {
        let header = FrameHeader {
            command: Command::Waste,
            stream_id: 0,
            length: 0,
        };
        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf);
        let decoded = FrameHeader::decode(&buf);
        assert_eq!(decoded.command, Command::Waste);
        assert_eq!(decoded.stream_id, 0);
        assert_eq!(decoded.length, 0);
    }

    #[test]
    fn test_header_binary_layout() {
        let header = FrameHeader {
            command: Command::Psh,
            stream_id: 0x01020304,
            length: 0x0506,
        };
        let mut buf = [0u8; HEADER_SIZE];
        header.encode(&mut buf);
        assert_eq!(buf, [2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }
}
