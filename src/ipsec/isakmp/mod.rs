#![allow(non_snake_case)]

use util::{hex_dump,hex_dump_nospace,ParseResult};
use self::header::Header;
use self::payload::Payload;

mod header;
mod payload;


#[deriving(Show)]
enum PayloadKind
{
    None,

    SA,         // Security Association
    P,          // Proposal
    T,          // Transform
    KE,         // Key Exchange
    ID,         // Identification
    CERT,       // Certificate
    CR,         // Certificate Request
    HASH,       // Hash
    SIG,        // Signature
    NONCE,      // Nonce
    N,          // Notification
    D,          // Delete
    VID,        // Vendor ID

    Unknown,    // Unknown
}


fn payl_kind(ty: uint) -> PayloadKind
{
    match ty
    {
         0 => PayloadKind::None,
         1 => PayloadKind::SA,
         2 => PayloadKind::P,
         3 => PayloadKind::T,
         4 => PayloadKind::KE,
         5 => PayloadKind::ID,
         6 => PayloadKind::CERT,
         7 => PayloadKind::CR,
         8 => PayloadKind::HASH,
         9 => PayloadKind::SIG,
        10 => PayloadKind::NONCE,
        11 => PayloadKind::N,
        12 => PayloadKind::D,
        13 => PayloadKind::VID,
         _ => PayloadKind::Unknown,
    }
}


fn parse_packet(dat: &[u8]) -> ParseResult<()>
{
    let (head,tmp) = try!(Header::parse(dat));

    println!("{}", head);

    let mut rem = tmp;
    let mut ty  = head.NextPayload;

    while rem.len() > 0
    {
        let (payl,tmp) = try!(Payload::parse(rem));

        println!("{}", payl);

        match ty
        {
            PayloadKind::VID => { try!(parse_vid(payl.Payload)); }
            _ => { print!("{}", hex_dump(payl.Payload)); }
        }

        rem = tmp;
        ty  = payl.NextPayload;
    }

    Ok(((),rem))
}

fn parse_vid(dat: &[u8]) -> ParseResult<()>
{
    match dat
    {
        [0x4a,0x13,0x1c,0x81,0x07,0x03,0x58,0x45,
         0x5c,0x57,0x28,0xf2,0x0e,0x95,0x45,0x2f]
            => println!("ISAKMP::VID <RFC3947>"),

        [0x44,0x85,0x15,0x2d,0x18,0xb6,0xbb,0xcd,
         0x0b,0xe8,0xa8,0x46,0x95,0x79,0xdd,0xcc]
            => println!("ISAKMP::VID <draft-ietf-ipsec-nat-t-ike-00>"),

        [0xcd,0x60,0x46,0x43,0x35,0xdf,0x21,0xf8,
         0x7c,0xfd,0xb2,0xfc,0x68,0xb6,0xa4,0x48] |
        [0x90,0xcb,0x80,0x91,0x3e,0xbb,0x69,0x6e,
         0x08,0x63,0x81,0xb5,0xec,0x42,0x7b,0x1f]
            => println!("ISAKMP::VID <draft-ietf-ipsec-nat-t-ike-02>"),

        [0xaf,0xca,0xd7,0x13,0x68,0xa1,0xf1,0xc9,
         0x6b,0x86,0x96,0xfc,0x77,0x57,0x01,0x00]
            => println!("ISAKMP::VID <Dead Peer Detection v1.0>"),

        [0x40,0x48,0xb7,0xd5,0x6e,0xbc,0xe8,0x85,
         0x25,0xe7,0xde,0x7f,0x00,0xd6,0xc2,0xd3,frag..]
            => println!("ISAKMP::VID <FRAGMENTATION>[{}]", hex_dump_nospace(frag)),

        _ => print!("{}", hex_dump(dat))
    }

    Ok(((),dat[..0]))
}

pub fn dump_packet(dat: &[u8])
{
    match parse_packet(dat)
    {
        Ok((_,dat)) => print!("{}", hex_dump(dat)),
        Err(_) => println!("Error"),
    }
}
