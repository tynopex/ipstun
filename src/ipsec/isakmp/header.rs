use std::fmt;
use util::{ParseResult,get_u8_4,get_u8_8,get_u32,hex_dump_nospace};
use util::PacketError::{TruncatedPacket,InvalidPacket};
use super::{PayloadKind,payl_kind};


pub struct Header
{
    pub InitiatorCookie: [u8,..8],
    pub ResponderCookie: [u8,..8],
    pub NextPayload: PayloadKind,
    pub Version: u8,
    pub ExchangeType: u8,
    pub Flags: u8,
    pub MessageID: [u8,..4],
    pub Length: u32,
}


impl Header
{
    pub fn Size() -> uint { 28 }

    pub fn parse<'a>(dat: &'a [u8]) -> ParseResult<'a, Header>
    {
        if dat.len() < Header::Size()
        {
            return Err(TruncatedPacket);
        }

        let header = Header {
            InitiatorCookie: get_u8_8(dat[0..]),
            ResponderCookie: get_u8_8(dat[8..]),
            NextPayload: payl_kind(dat[16] as uint),
            Version: dat[17],
            ExchangeType: dat[18],
            Flags: dat[19],
            MessageID: get_u8_4(dat[20..]),
            Length: get_u32 (dat[24..]),
            };

        if header.Version != 0x10
        {
            return Err(InvalidPacket)
        }

        Ok((header, dat[Header::Size()..]))
    }

    pub fn flagEnc (&self) -> bool { (self.Flags & 0x01) != 0 }
    pub fn flagCmt (&self) -> bool { (self.Flags & 0x02) != 0 }
    pub fn flagAuth(&self) -> bool { (self.Flags & 0x04) != 0 }
}


impl fmt::Show for Header
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        try!(write!(f, "ISAKMP::Header"));
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
