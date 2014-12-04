#![allow(non_snake_case)]

use util::{hex_dump,ParseResult};
use self::packet::Packet;
use self::payload::Payload;
use self::vid::VendorExt;
use self::assoc::SecAssoc;

mod packet;
mod payload;
mod vid;
mod assoc;


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
    let (head,_) = try!(Packet::parse(dat));

    println!("{}", head);

    let mut rem = head.Payload;
    let mut ty  = head.NextPayload;

    while rem.len() > 0
    {
        let (payl,tmp) = try!(Payload::parse(rem));

        println!("{}", payl);

        match ty
        {
            PayloadKind::SA => {
                let (sa,_) = try!(SecAssoc::parse(payl.Payload));
                println!("{}", sa);
                print!("{}", hex_dump(payl.Payload));
                }

            PayloadKind::VID => {
                let (vid,_) = try!(VendorExt::parse(payl.Payload));
                println!("{}", vid);
                }

            _ => { print!("{}", hex_dump(payl.Payload)); }
        }

        rem = tmp;
        ty  = payl.NextPayload;
    }

    Ok(((),rem))
}

pub fn dump_packet(dat: &[u8])
{
    match parse_packet(dat)
    {
        Ok((_,dat)) => print!("{}", hex_dump(dat)),
        Err(_) => println!("Error"),
    }
}
