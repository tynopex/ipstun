use std::fmt;
use util::{ParseResult,get_u8_4,get_u8_8,get_u32,hex_dump_nospace};
use util::PacketError::{TruncatedPacket,InvalidPacket,IllegalPacket,UnsupportedPacket};
use super::{PayloadKind,payl_kind};
use super::payload::PayloadIter;


#[derive(Show,Copy)]
enum ExchangeKind
{
    NONE,
    Base,
    IdentityProtection,
    AuthenticationOnly,
    Aggressive,
    Informational,
    Unknown(u8),
}


#[derive(Copy)]
pub struct Packet<'a>
{
    pub InitiatorCookie: [u8; 8],
    pub ResponderCookie: [u8; 8],
    pub NextPayload: PayloadKind,
    pub Version: u8,
    pub ExchangeType: ExchangeKind,
    pub Flags: u8,
    pub MessageID: [u8; 4],
    pub Length: u32,

    pub Payload: &'a [u8],
}


impl<'a> Packet<'a>
{
    pub fn HeaderSize() -> uint { 28 }

    pub fn parse(dat: &[u8]) -> ParseResult<Packet>
    {
        if dat.len() < Packet::HeaderSize()
        {
            return Err(TruncatedPacket);
        }

        let ex = match dat[18] {
            0 => ExchangeKind::NONE,
            1 => ExchangeKind::Base,
            2 => ExchangeKind::IdentityProtection,
            3 => ExchangeKind::AuthenticationOnly,
            4 => ExchangeKind::Aggressive,
            5 => ExchangeKind::Informational,
            x => ExchangeKind::Unknown(x),
            };

        let header = Packet {
            InitiatorCookie: get_u8_8(dat[0..]),
            ResponderCookie: get_u8_8(dat[8..]),
            NextPayload: payl_kind(dat[16] as uint),
            Version: dat[17],
            ExchangeType: ex,
            Flags: dat[19],
            MessageID: get_u8_4(dat[20..]),
            Length: get_u32(dat[24..]),
            Payload: dat[28..],
            };

        if header.Version != 0x10
        {
            return Err(InvalidPacket);
        }

        match header.ExchangeType
        {
            ExchangeKind::IdentityProtection => (),
            _ => return Err(UnsupportedPacket),
        }

        if dat.len() < header.Length as uint
        {
            return Err(TruncatedPacket);
        }

        if dat.len() > header.Length as uint
        {
            return Err(IllegalPacket);
        }

        Ok(header)
    }

    pub fn flagEnc (&self) -> bool { (self.Flags & 0x01) != 0 }
    pub fn flagCmt (&self) -> bool { (self.Flags & 0x02) != 0 }
    pub fn flagAuth(&self) -> bool { (self.Flags & 0x04) != 0 }

    pub fn iter(&self) -> PayloadIter<'a>
    {
        PayloadIter { raw: self.Payload, next_type: self.NextPayload }
    }
}


impl<'a> fmt::Show for Packet<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        try!(write!(f, "ISAKMP::Packet"));
        try!(write!(f, " ICookie[{}]", hex_dump_nospace(&self.InitiatorCookie)));
        try!(write!(f, " RCookie[{}]", hex_dump_nospace(&self.ResponderCookie)));
        try!(write!(f, " Next[{}]", self.NextPayload));
        try!(write!(f, " Ver[{}]", self.Version));
        try!(write!(f, " Exch[{}]", self.ExchangeType));

        try!(write!(f, " Flag["));
        if self.flagEnc()  { try!(write!(f, "E")); }
        if self.flagCmt()  { try!(write!(f, "C")); }
        if self.flagAuth() { try!(write!(f, "A")); }
        try!(write!(f, "]"));

        try!(write!(f, " MID[{}]", hex_dump_nospace(&self.MessageID)));
        try!(write!(f, " Len[{}]", self.Length));

        Ok(())
    }
}
