//! For-reconnect packet implementation.
//!
//! Received carrying an opaque reconnect token used when the client is
//! instructed to reconnect.
//!
//! Note: this is distinct from the `Reconnect` packet (ID 45), which carries a
//! full host/port/key payload. This packet (ID 218) carries only a single
//! string.

use super::traits::RotmgPacket;
use super::PacketReader;
use std::io;

/// For-reconnect packet (ID 218) - Incoming
///
/// Carries an opaque reconnect-info string (a 16-bit length-prefixed string).
#[derive(Clone)]
pub struct ForReconnectPacket {
    /// Opaque reconnect information token.
    pub reconnect_info: String,
}

impl std::fmt::Debug for ForReconnectPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForReconnectPacket").finish_non_exhaustive()
    }
}

impl RotmgPacket for ForReconnectPacket {
    fn deserialize(reader: &mut PacketReader) -> io::Result<Self> {
        let reconnect_info = reader.read_string()?;

        Ok(Self { reconnect_info })
    }

    fn description(&self) -> String {
        "ForReconnect".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_description_omit_reconnect_token() {
        let packet = ForReconnectPacket {
            reconnect_info: "synthetic-reconnect-secret".to_string(),
        };
        assert_eq!(packet.description(), "ForReconnect");
        assert!(!format!("{packet:?}").contains("synthetic-reconnect-secret"));
        let wrapped = super::super::ParsedPacket::ForReconnect(packet);
        assert!(!format!("{wrapped:?}").contains("synthetic-reconnect-secret"));
    }

    fn build_bytes(info: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(info.len() as u16).to_be_bytes());
        data.extend_from_slice(info.as_bytes());
        data
    }

    #[test]
    fn test_for_reconnect_deserialize() {
        let data = build_bytes("token-abc-123");
        let mut reader = PacketReader::new(&data);
        let packet = ForReconnectPacket::deserialize(&mut reader).unwrap();

        assert_eq!(packet.reconnect_info, "token-abc-123");
        assert!(reader.is_fully_parsed());
    }

    #[test]
    fn test_for_reconnect_empty() {
        let data = build_bytes("");
        let mut reader = PacketReader::new(&data);
        let packet = ForReconnectPacket::deserialize(&mut reader).unwrap();

        assert_eq!(packet.reconnect_info, "");
    }
}
