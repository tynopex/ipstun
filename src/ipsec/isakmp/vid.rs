use std::fmt;
use util::{ParseResult,get_u32};


pub enum VendorExt<'a>
{
    RFC3947,
    NatTDraft00,
    NatTDraft02,
    DeadPeerDetection,
    Fragmentation(u32),
    Unknown(&'a [u8]),
}


impl<'a> VendorExt<'a>
{
    pub fn parse(dat: &[u8]) -> ParseResult<VendorExt>
    {
        let mut vid = VendorExt::Unknown(dat);

        if dat.len() >= 16
        {
            let (hdr, arg) = dat.split_at(16);

            if      hdr == [0x4a,0x13,0x1c,0x81,0x07,0x03,0x58,0x45,
                            0x5c,0x57,0x28,0xf2,0x0e,0x95,0x45,0x2f]
            {
                vid = VendorExt::RFC3947;
            }
            else if hdr == [0x44,0x85,0x15,0x2d,0x18,0xb6,0xbb,0xcd,
                            0x0b,0xe8,0xa8,0x46,0x95,0x79,0xdd,0xcc]
            {
                vid = VendorExt::NatTDraft00;
            }
            else if hdr == [0xcf,0x60,0x46,0x43,0x35,0xdf,0x21,0xf8,
                            0x7c,0xfd,0xb2,0xfc,0x68,0xb6,0xa4,0x48]
            {
                vid = VendorExt::NatTDraft02;
            }
            else if hdr == [0x90,0xcb,0x80,0x91,0x3e,0xbb,0x69,0x6e,
                            0x08,0x63,0x81,0xb5,0xec,0x42,0x7b,0x1f]
            {
                vid = VendorExt::NatTDraft02;
            }
            else if hdr == [0xaf,0xca,0xd7,0x13,0x68,0xa1,0xf1,0xc9,
                            0x6b,0x86,0x96,0xfc,0x77,0x57,0x01,0x00]
            {
                vid = VendorExt::DeadPeerDetection;
            }
            else if hdr == [0x40,0x48,0xb7,0xd5,0x6e,0xbc,0xe8,0x85,
                            0x25,0xe7,0xde,0x7f,0x00,0xd6,0xc2,0xd3]
            {
                if arg.len() == 4
                {
                    vid = VendorExt::Fragmentation(get_u32(arg));
                }
            }
        }

        Ok(vid)
    }
}


impl<'a> fmt::Debug for VendorExt<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        use util::hex_dump_nospace as hex;

        match *self
        {
            VendorExt::RFC3947
                => try!(write!(f, "ISAKMP::VID <RFC3947>")),

            VendorExt::NatTDraft00
                => try!(write!(f, "ISAKMP::VID <draft-ietf-ipsec-nat-t-ike-00>")),

            VendorExt::NatTDraft02
                => try!(write!(f, "ISAKMP::VID <draft-ietf-ipsec-nat-t-ike-02>")),

            VendorExt::DeadPeerDetection
                => try!(write!(f, "ISAKMP::VID <Dead Peer Detection v1.0>")),

            VendorExt::Fragmentation(cap)
                => try!(write!(f, "ISAKMP::VID <FRAGMENTATION>[{:X}]", cap)),

            VendorExt::Unknown(raw)
                => try!(write!(f, "ISAKMP::VID Unknown[{}]", hex(raw))),
        }

        Ok(())
    }
}
