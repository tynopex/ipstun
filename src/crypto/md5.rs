use std::mem;
use std::iter;

const C_IDX: [uint; 64] =
[
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
    5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
    0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9,
];

const C_ROT: [uint; 64] =
[
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
];

// FLOOR( SIN( i + 1 ) * 2^32 )
const C_SIN: [u32; 64] =
[
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[allow(unused_parens)]
fn get_blk(raw: &[u8], i: uint, len: uint, rem: uint, nbl: uint) -> [u32; 16]
{
    let blen = ( len * 8 );
    let brem = ( rem * 8 );
    let base = ( i * 64 );

    let mut blk: [u32; 16] = unsafe { mem::uninitialized() };

    for j in iter::range_step::<uint>(0, 64, 4)
    {
        let jj = base + j;
        let mut x: u32 = 0;

        if jj + 0 < len { x += ( (raw[jj + 0] as u32)       ); }
        if jj + 1 < len { x += ( (raw[jj + 1] as u32) <<  8 ); }
        if jj + 2 < len { x += ( (raw[jj + 2] as u32) << 16 ); }
        if jj + 3 < len { x += ( (raw[jj + 3] as u32) << 24 ); }

        blk[j / 4] = x;
    }

    if ( i == ( len / 64 ) )
    {
        blk[brem / 32] += ( (0x80 as u32) << ( brem % 32 ) );
    }

    if ( i == ( nbl -  1 ) )
    {
        blk[14] = ( (blen as u64)       ) as u32;
        blk[15] = ( (blen as u64) >> 32 ) as u32;
    }

    blk
}

#[allow(non_snake_case)]
fn XX(a: u32, b: u32, c: u32, d: u32, i: uint, X: &[u32]) -> u32
{
    // b + ( ( a + FN(b,c,d) + X[k] + T[i] ) <<< s )

    let k: uint = C_IDX[i];
    let s: uint = C_ROT[i];

    let fx: u32 = match i / 16
    {
        0 => ( b & c ) + ( !b & d ),    // F
        1 => ( b & d ) + ( c & !d ),    // G
        2 => ( b ^ c ^ d ),             // H
        3 => c ^ ( b | !d ),            // I
        _ => panic!()
    };

    let xx: u32 = a + fx + X[k] + C_SIN[i];
    let xx: u32 = ( xx << s ) + ( xx >> ( 32 - s ) );
    let xx: u32 = b + xx;

    xx
}

#[allow(non_snake_case)]
pub fn hash(raw: &[u8]) -> [u8; 16]
{
    let len = raw.len();

    let rem = len % 64;
    let pad = if rem < 56 { 56 - rem } else { 120 - rem };
    let nbl = ( len + pad + 8 ) / 64;

    let mut ctx: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    for i in iter::range(0, nbl)
    {
        let blk = get_blk( raw, i, len, rem, nbl );

        let mut A: u32 = ctx[0];
        let mut B: u32 = ctx[1];
        let mut C: u32 = ctx[2];
        let mut D: u32 = ctx[3];

        for j in iter::range_step(0, 64, 4)
        {
            A = XX( A, B, C, D, j+0, &blk );
            D = XX( D, A, B, C, j+1, &blk );
            C = XX( C, D, A, B, j+2, &blk );
            B = XX( B, C, D, A, j+3, &blk );
        }

        ctx[0] += A;
        ctx[1] += B;
        ctx[2] += C;
        ctx[3] += D;
    }

    let mut md5: [u8; 16] = unsafe { mem::uninitialized() };

    for j in iter::range(0, 4)
    {
        for i in iter::range(0, 4)
        {
            md5[i + j*4] = ( ctx[j] >> (8 * i) ) as u8;
        }
    }

    md5
}


#[cfg(test)]
mod tests
{
    extern crate test;
    extern crate serialize;

    use std::mem;
    use std::rand;

    fn do_md5(msg: &str) -> String
    {
        use self::serialize::hex::ToHex;

        let hash = super::hash( msg.as_bytes() );

        hash.to_hex()
    }

    #[test]
    fn test_strings()
    {
        assert_eq!("d41d8cd98f00b204e9800998ecf8427e", do_md5(""));
        assert_eq!("0cc175b9c0f1b6a831c399e269772661", do_md5("a"));
        assert_eq!("8a7319dbf6544a7422c9e25452580ea5", do_md5("abcdefghijklmno"));
        assert_eq!("1d64dce239c4437b7736041db089e1b9", do_md5("abcdefghijklmnop"));
        assert_eq!("9a8d9845a6b4d82dfcb2c2e35162c830", do_md5("abcdefghijklmnopq"));
        assert_eq!("6d2286301265512f019781cc0ce7a39f", do_md5("abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    #[bench]
    fn test_speed(b: &mut test::Bencher)
    {
        use std::rand::Rng;
        use std::str::from_utf8_unchecked;

        // Random &str
        let mut raw: [u8; 4096] = unsafe { mem::uninitialized() };
        rand::thread_rng().fill_bytes(&mut raw);
        let msg = unsafe { from_utf8_unchecked(&raw) };

        b.iter(|| do_md5(msg));
        b.bytes = 4096;
    }
}
