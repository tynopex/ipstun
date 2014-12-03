use std::fmt;
use util::{ParseResult,get_u16};
use util::PacketError::{TruncatedPacket,IllegalPacket};
use super::{PayloadKind,payl_kind};


pub struct Payload<'a>
{
    pub NextPayload: PayloadKind,
    pub Length: uint,
    pub Payload: &'a [u8],
}


impl<'a> Payload<'a>
{
    pub fn Size() -> uint { 4 }

    pub fn parse<'a>(dat: &'a [u8]) -> ParseResult<'a, Payload>
    {
        if dat.len() < Payload::Size()
        {
            return Err(TruncatedPacket);
        }

        let len = get_u16(dat[2..]) as uint;

        if len < Payload::Size()
        {
            return Err(IllegalPacket);
        }

        if len > dat.len()
        {
            return Err(TruncatedPacket);
        }

        let payload = Payload {
            NextPayload: payl_kind(dat[0] as uint),
            Length: len,
            Payload: dat[Payload::Size()..len],
            };

        Ok((payload, dat[len..]))
    }
}


impl<'a> fmt::Show for Payload<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        try!(write!(f, "ISAKMP::Payload"));
        try!(write!(f, " Next[{}]", self.NextPayload));
        try!(write!(f, " Len[{}]", self.Length));

        Ok(())
    }
}
