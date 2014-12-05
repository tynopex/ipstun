#![allow(non_snake_case)]

use self::packet::Packet;
use self::payload::Payload;
use self::vid::VendorExt;
use self::assoc::SecAssoc;
use self::proposal::Proposal;
use self::transform::Transform;
use self::attr::Attribute;

mod visit;
mod packet;
mod payload;
mod vid;
mod assoc;
mod proposal;
mod transform;
mod attr;


#[deriving(Show)]
pub enum PayloadKind
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


struct DumpPacketVisitor;

impl visit::PacketVisitor for DumpPacketVisitor
{
    fn header(&self, x: Packet) { println!("{}", x); }
    fn payload(&self, _: PayloadKind, _: Payload) { }
    fn vendor_ext(&self, x: VendorExt) { println!(" {}", x); }
    fn sec_assoc(&self, x: SecAssoc) { println!(" {}", x); }
    fn proposal(&self, x: Proposal) { println!("  {}", x); }
    fn transform(&self, x: Transform) { println!("    {}", x); }
    fn attribute(&self, x: Attribute) { println!("     {}", x); }
}

pub fn dump_packet(dat: &[u8])
{
    let dump = DumpPacketVisitor;

    match visit::parse(&dump, dat)
    {
        Ok(()) => (),
        Err(e) => println!("ParseError({})", e),
    }
}
