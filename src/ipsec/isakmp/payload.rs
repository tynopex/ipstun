use std::fmt;
use std::iter;
use util::{ParseResult,PacketError,get_u16};
use util::PacketError::{TruncatedPacket,IllegalPacket};
use super::{PayloadKind,payl_kind};


pub struct Payload<'a>
{
    pub NextPayload: PayloadKind,
    pub Length: uint,
    pub Payload: &'a [u8],
}


pub struct PayloadIter<'a>
{
    pub next_type: PayloadKind,
    pub raw: &'a [u8],
}

pub type PayloadIterResult<'a> = Result<(PayloadKind, Payload<'a>), PacketError>;


impl<'a> Payload<'a>
{
    pub fn Size() -> uint { 4 }

    pub fn parse(dat: &[u8]) -> ParseResult<Payload>
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

        Ok(payload)
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


impl<'a> iter::Iterator<PayloadIterResult<'a>> for PayloadIter<'a>
{
    fn next(&mut self) -> Option<PayloadIterResult<'a>>
    {
        if self.raw.len() > 0
        {
            match Payload::parse(self.raw)
            {
                Err(e) => Some(Err(e)),
                Ok(payl) => {
                    let ty = self.next_type;

                    self.next_type = payl.NextPayload;
                    self.raw = self.raw[payl.Length..];

                    Some(Ok((ty,payl)))
                    },
            }
        }
        else
        {
            None
        }
    }
}
