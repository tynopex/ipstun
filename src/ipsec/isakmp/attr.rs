use std::fmt;
use std::iter;
use util::{ParseResult,PacketError,get_u16,hex_dump_nospace};
use util::PacketError::{TruncatedPacket};


pub struct Attribute<'a>
{
    pub key: u16,
    pub val: &'a [u8],
}

pub struct AttributeIter<'a>
{
    pub raw: &'a [u8],
}

pub type AttributeIterResult<'a> = Result<Attribute<'a>, PacketError>;


impl<'a> Attribute<'a>
{
    pub fn parse(dat: &[u8]) -> ParseResult<(Attribute, &[u8])>
    {
        if dat.len() < 4
        {
            return Err(TruncatedPacket);
        }

        let flags = get_u16(dat[0..]);

        let (hlen,len) = match flags & 0x8000 {
            0 => (4, 4 + get_u16(dat[2..]) as uint),
            _ => (2, 4),
            };

        if dat.len() < len
        {
            return Err(TruncatedPacket);
        }

        let attr = Attribute {
            key: flags & 0x7FFF,
            val: dat[hlen..len],
            };

        Ok((attr,dat[len..]))
    }
}


impl<'a> fmt::Show for Attribute<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        try!(write!(f, "ISAKMP::Attribute"));
        try!(write!(f, " Key[{}]", self.key));
        try!(write!(f, " Val[{}]", hex_dump_nospace(self.val)));

        Ok(())
    }
}


impl<'a> iter::Iterator<AttributeIterResult<'a>> for AttributeIter<'a>
{
    fn next(&mut self) -> Option<AttributeIterResult<'a>>
    {
        if self.raw.len() > 0
        {
            match Attribute::parse(self.raw)
            {
                Err(e) => Some(Err(e)),
                Ok((attr,rem)) => {
                    self.raw = rem;

                    Some(Ok(attr))
                    },
            }
        }
        else
        {
            None
        }
    }
}
