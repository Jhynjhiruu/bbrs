use binrw::{binrw, BinRead, BinResult, BinWrite};
use hex_literal::hex;
use morton_encoding::{morton_decode, morton_encode};
use sha1::{Digest, Sha1};
use soft_aes::aes::aes_enc_cbc;
use thiserror::Error;

use std::io::Cursor;
use std::mem::size_of;
use std::num::Wrapping;

pub type BbShaHash = [u8; 20];
pub type BbAesKey = [u8; 16];
pub type BbAesIv = [u8; 16];
pub type BbEccPrivateKey = [u8; 32];
pub type BbEccPublicKey = [u8; 64];
pub type BbId = u32;
pub type BbContentId = u32;
pub type BbServerName = [u8; 64];
pub type BbRsaSig2048 = [u8; 256];

pub const BLOCK_SIZE: usize = 16 * 1024;

const BOOTROM_HASH: BbShaHash = hex!("1663EFC4F08E1E20C244B38F3572325700D327C1");

pub trait HashHex {
    fn to_hex(&self) -> String;
}

macro_rules! hash_hex {
    ($($t:ty), *) => {
        $(
        impl HashHex for $t {
            fn to_hex(&self) -> String {
                self.map(|b| format!("{b:02X}")).join("")
            }
        }
    )*
    };
}

// don't need to do more than this because these typedefs cover all the others
hash_hex!(
    BbShaHash,
    BbAesKey,
    BbEccPrivateKey,
    BbEccPublicKey,
    BbRsaSig2048
);

#[binrw]
#[derive(Debug)]
pub struct Virage2 {
    pub sk_hash: BbShaHash,

    pub rom_patch: [u32; Self::NUM_ROM_PATCH_WORDS],

    pub pub_key: BbEccPublicKey,

    pub bbid: BbId,

    pub priv_key: BbEccPrivateKey,

    pub boot_app_key: BbAesKey,
    pub recrypt_list_key: BbAesKey,
    pub app_state_key: BbAesKey,
    pub self_msg_key: BbAesKey,

    pub csum_adjust: u32,

    pub jtag_enable: u32,
}

impl Virage2 {
    const NUM_ROM_PATCH_WORDS: usize = 16;

    const SIZE: usize = 256;

    const CSUM_MAGIC: u32 = 0x00BBC0DE;

    pub fn read_from_buf(buf: &[u8]) -> BinResult<Self> {
        if buf.len() != Self::SIZE {
            return Err(binrw::Error::AssertFail {
                pos: 0,
                message: format!(
                    "incorrect size (got {} bytes, expected {})",
                    buf.len(),
                    Self::SIZE
                ),
            });
        }

        let csum: Wrapping<_> = buf
            .chunks_exact(4)
            .map(|i| u32::from_be_bytes(i.try_into().unwrap()))
            .map(Wrapping)
            .sum();

        if csum.0 != Self::CSUM_MAGIC {
            return Err(binrw::Error::BadMagic {
                pos: 0,
                found: Box::new(format!(
                    "Invalid checksum (got {:08X}, expected {:08X})",
                    csum.0,
                    Self::CSUM_MAGIC
                )),
            });
        }

        let mut cursor = Cursor::new(buf);
        <_>::read_be(&mut cursor)
    }
}

#[derive(Debug, Error)]
pub enum BootromError {
    #[error("Invalid bootrom SHA-1 hash (got {0}, expected {})", BOOTROM_HASH.to_hex())]
    InvalidHash(String),
}

pub const SK_KEY_START: usize = 0x1460;
pub const SK_IV_START: usize = 0x1470;

pub fn bootrom_keys(bootrom: &[u8]) -> Result<(BbAesKey, BbAesIv), BootromError> {
    let mut hasher = Sha1::new();

    hasher.update(bootrom);

    let bootrom_hash: BbShaHash = hasher.finalize().into();

    if bootrom_hash != BOOTROM_HASH {
        return Err(BootromError::InvalidHash(bootrom_hash.to_hex()));
    }

    let sk_key = bootrom[SK_KEY_START..SK_KEY_START + size_of::<BbAesKey>()]
        .try_into()
        .unwrap();
    let sk_iv = bootrom[SK_IV_START..SK_IV_START + size_of::<BbAesIv>()]
        .try_into()
        .unwrap();

    Ok((sk_key, sk_iv))
}

#[binrw]
#[derive(Debug)]
pub struct CmdHead {
    #[brw(pad_before(4))]
    pub ca_crl_version: u32,
    pub cp_crl_version: u32,

    pub size: u32,
    pub desc_flags: u32,
    pub common_cmd_iv: BbAesIv,

    pub hash: BbShaHash,
    pub iv: BbAesIv,

    pub exec_flags: u32,
    pub hw_access_rights: u32,
    pub secure_kernel_rights: u32,

    pub bbid: u32,

    pub issuer: BbServerName,

    pub id: BbContentId,
    pub key: BbAesKey,

    pub content_meta_data_sign: BbRsaSig2048,
}

impl CmdHead {
    pub const SIZE: usize = 0x1AC;

    pub fn read_from_buf(buf: &[u8]) -> BinResult<Self> {
        if buf.len() != Self::SIZE {
            return Err(binrw::Error::AssertFail {
                pos: 0,
                message: format!(
                    "incorrect size (got {} bytes, expected {})",
                    buf.len(),
                    Self::SIZE
                ),
            });
        }

        // maybe check the signature, eventually

        let mut cursor = Cursor::new(buf);
        <_>::read_be(&mut cursor)
    }

    pub fn to_buf(&self) -> BinResult<Vec<u8>> {
        let mut rv = vec![];
        let mut cursor = Cursor::new(&mut rv);
        self.write_be(&mut cursor)?;

        Ok(rv)
    }

    pub fn new_unsigned(
        key: BbAesKey,
        iv: BbAesIv,
        common_key: BbAesKey,
        key_iv: BbAesIv,
        size: u32,
        cid: u32,
    ) -> Self {
        let enc_key = aes_enc_cbc(&key, &common_key, &key_iv, None).expect("encryption failed");

        // horrible hack so emoose's iQueTool code doesn't die on these CMD heads
        // eventually I'll write a replacement and this won't be necessary
        let issuer = *b"Root\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

        Self {
            ca_crl_version: 0,
            cp_crl_version: 1,
            size,
            desc_flags: 1,
            common_cmd_iv: key_iv,
            hash: Default::default(),
            iv,
            exec_flags: 0,
            hw_access_rights: 0xFFFFFFFF,
            secure_kernel_rights: 0xFFFFFFFF,
            bbid: 0,
            issuer,
            id: cid,
            key: enc_key.try_into().unwrap(),
            content_meta_data_sign: [0; 256],
        }
    }
}

pub type Ecc = (u8, u8, u8);

/// Most implementations of this ECC algorithm use a lookup table, which was copy-pasted from some unknown original source.
/// That table was generated by a program distributed as gen-ecc.c, and is reproduced here:
///
/// const COLUMN_PARITY_TABLE: [u8; 256] = [
///     0x00, 0x55, 0x59, 0x0C, 0x65, 0x30, 0x3C, 0x69, 0x69, 0x3C, 0x30, 0x65, 0x0C, 0x59, 0x55, 0x00,
///     0x95, 0xC0, 0xCC, 0x99, 0xF0, 0xA5, 0xA9, 0xFC, 0xFC, 0xA9, 0xA5, 0xF0, 0x99, 0xCC, 0xC0, 0x95,
///     0x99, 0xCC, 0xC0, 0x95, 0xFC, 0xA9, 0xA5, 0xF0, 0xF0, 0xA5, 0xA9, 0xFC, 0x95, 0xC0, 0xCC, 0x99,
///     0x0C, 0x59, 0x55, 0x00, 0x69, 0x3C, 0x30, 0x65, 0x65, 0x30, 0x3C, 0x69, 0x00, 0x55, 0x59, 0x0C,
///     0xA5, 0xF0, 0xFC, 0xA9, 0xC0, 0x95, 0x99, 0xCC, 0xCC, 0x99, 0x95, 0xC0, 0xA9, 0xFC, 0xF0, 0xA5,
///     0x30, 0x65, 0x69, 0x3C, 0x55, 0x00, 0x0C, 0x59, 0x59, 0x0C, 0x00, 0x55, 0x3C, 0x69, 0x65, 0x30,
///     0x3C, 0x69, 0x65, 0x30, 0x59, 0x0C, 0x00, 0x55, 0x55, 0x00, 0x0C, 0x59, 0x30, 0x65, 0x69, 0x3C,
///     0xA9, 0xFC, 0xF0, 0xA5, 0xCC, 0x99, 0x95, 0xC0, 0xC0, 0x95, 0x99, 0xCC, 0xA5, 0xF0, 0xFC, 0xA9,
///     0xA9, 0xFC, 0xF0, 0xA5, 0xCC, 0x99, 0x95, 0xC0, 0xC0, 0x95, 0x99, 0xCC, 0xA5, 0xF0, 0xFC, 0xA9,
///     0x3C, 0x69, 0x65, 0x30, 0x59, 0x0C, 0x00, 0x55, 0x55, 0x00, 0x0C, 0x59, 0x30, 0x65, 0x69, 0x3C,
///     0x30, 0x65, 0x69, 0x3C, 0x55, 0x00, 0x0C, 0x59, 0x59, 0x0C, 0x00, 0x55, 0x3C, 0x69, 0x65, 0x30,
///     0xA5, 0xF0, 0xFC, 0xA9, 0xC0, 0x95, 0x99, 0xCC, 0xCC, 0x99, 0x95, 0xC0, 0xA9, 0xFC, 0xF0, 0xA5,
///     0x0C, 0x59, 0x55, 0x00, 0x69, 0x3C, 0x30, 0x65, 0x65, 0x30, 0x3C, 0x69, 0x00, 0x55, 0x59, 0x0C,
///     0x99, 0xCC, 0xC0, 0x95, 0xFC, 0xA9, 0xA5, 0xF0, 0xF0, 0xA5, 0xA9, 0xFC, 0x95, 0xC0, 0xCC, 0x99,
///     0x95, 0xC0, 0xCC, 0x99, 0xF0, 0xA5, 0xA9, 0xFC, 0xFC, 0xA9, 0xA5, 0xF0, 0x99, 0xCC, 0xC0, 0x95,
///     0x00, 0x55, 0x59, 0x0C, 0x65, 0x30, 0x3C, 0x69, 0x69, 0x3C, 0x30, 0x65, 0x0C, 0x59, 0x55, 0x00,
/// ];
///
/// This table represents the "column parity" of each byte. That is, for each number n,
///     - bit 7 is the parity of bits 4-7 (inclusive) of n
///     - bit 6 is the parity of bits 0-3 of n
///     - bit 5 is the parity of bits 2-3 and 6-7 of n
///     - bit 4 is the parity of bits 0-1 and 4-5 of n
///     - bit 3 is the parity of bits 1, 3, 5 and 7 of n
///     - bit 2 is the parity of bits 0, 2, 4 and 6 of n
///     - bit 1 is always 0
///     - bit 0 is the parity of n
///
/// A seemingly older version of the algorithm rotated each entry to the right 2 bits (that is, so that bit 6 is the parity of n, instead of bit 0).
///
///
/// The ECC algorithm itself is as follows:
///
/// Start by initialising 3 variables: column_parity; line_parity; and line_parity_prime.
/// Then, for each byte i in the input,
///     - use i as an index into the lookup table and retrieve the byte
///     - set column_parity = column_parity ^ the value from the table (where ^ is xor)
///     - if the value from the table had bit 0 set - i.e., the parity of i is 1 - set line_parity = line_parity ^ the index of i in the data,
///         and set line_parity_prime = line_parity_prime ^ ~(the index of i in the data), where ~ is binary complement (! in Rust)
///
/// Next, Morton-encode line_parity and line_parity_prime.
/// Shift column_parity left two bits and set bits 0 and 1 to true (yes, this means that calculating the upper bits of the lookup table was useless)
///     and split out the two bytes of the Morton-encoded line_parity variables..
/// Take the complement of all 3 bytes.
/// The ECC is the two bytes from the Morton-encoded line_parity variables and then column_parity (post-shifting). You'll probably want to play around with stuff a bit,
///     since it's unlikely that you'll get both the bit ordering of the Morton encoding and the endianness of the conversion right first try. Use the data in this file as a test.
///
///
/// To decode the ECC data, first start by calculating the ECC bytes of the data you're given.
/// Then, take the xor of each byte of the calculated ECC and the provided ECC. We'll call these d0, d1 and d2, corresponding to bytes 0, 1 and 2 of the ECC.
///
/// If d0, d1 and d2 are all 0, then that means that there were no errors detected in the data.
///     (This doesn't necessarily mean that there actually are no errors, just that the data matches the ECC provided. It could still be wrong.)
///
/// Next, for each xored byte (d0, d1, d2), take that byte and xor it with itself shifted right by one bit. We'll call these x0, x1 and x2.
///     I'm... not entirely sure what this accomplishes, but given that the bits were interleaved earlier such that each bit is next to its complement,
///     this probably does something to compare each field against its complement in a useful way. I could probably figure it out, but I don't really care.
///     Perhaps you can look at it and tell me?
/// If x0 anded with 0x55 is equal to 0x55 - i.e. bits 0, 2, 4 and 6 are all set - and x1 anded with 0x55 is equal to 0x55, and x2 anded with 0x54 is equal to 0x54
///     (not a typo! d2 is the column parity, and d0 and d1 are both line parities, so d2 is treated differently), then this signifies a correctable single bit error.
/// To correct this single bit error,
///     - Morton-decode the u16 formed by concatenating d0 and d1. The lower byte is the index into the data of the incorrect byte.
///     - Morton-decode d2. The lower byte, shifted right by 1 bit, is the index into the byte of the bit to flip.
///     - Flip the bit, by finding the byte at the correct index, and xoring it with (1 << the index of the bit to flip), where << is shift left.
///
/// If the total number of bits set in d0, d1 and d2 combined is exactly equal to 1, then there's an error in the ECC.
/// This could either indicate that the provided ECC was wrong, or that there was an error in transmission such that the correct ECC is exactly one bit away from the provided ECC.
/// An error of that kind is extremely unlikely, given how the algorithm is designed, so it's most likely that the provided ECC was wrong.
/// You can probably just return the correct ECC in this case.
///
/// If none of the above conditions hold, then there's an uncorrectable error in the data. That means that at least two bits were flipped somewhere.
/// If the data is important, then now would be a great time to either throw up an error message of some kind, or just cry. Whoops.
///
///
///
/// My Rust implementation is a little bit janky, because I wanted to fully understand how the algorithm for generating the ECC data works.
/// I discovered that there's a really rather nice way of generating the table data on the fly, which really helped me understand what it's doing.
/// Essentially, rather than xoring column_parity with a value retrieved from the lookup table, we can instead work out which bits to flip as follows:
/// For each bit in a given number n, that bit affects the parity of some set of bits in the lookup table entry for n.
/// It turns out that that set of bits is equal to the complement of the index of that bit in n, Morton-encoded with the index. Try and work out why this is -
///     it's really satisfying to figure out and it's a really neat thing to spot.
/// So, my code loops through each bit in each byte in the input, and xors column_parity with the Morton encoding of the normal form and complement of the index,
///     shifted left so I don't have to do it later and ored with 1. I don't know if this is faster than using a lookup table - in fact, it almost certainly isn't - but
///     Rust's optimiser is pretty good and writing the code like this helped me understand it a lot better.
/// I also initialise all of the parity variables to 0xFF instead of inverting them at the end.
/// Have fun!
/// Also included in this code is a binrw struct detailing the layout of spare data blocks from the iQue Player's NAND, since I didn't really have anywhere else to put them.
///
///
/// This implementation © Jhynjhiruu 2023, 2024.
/// Licensed under the GNU GPL v2.
/// Original copyright notice reproduced here:
///
///
/// YAFFS: Yet Another Flash File System. A NAND-flash specific file system.
///
/// Copyright (C) 2002-2011 Aleph One Ltd.
///   for Toby Churchill Ltd and Brightstar Engineering
///
/// Created by Charles Manning <charles@aleph1.co.uk>
///
/// This program is free software; you can redistribute it and/or modify
/// it under the terms of the GNU General Public License version 2 as
/// published by the Free Software Foundation.
///
///
///
/// Original algorithm notes:
///
///
/// This code implements the ECC algorithm used in SmartMedia.
///
/// The ECC comprises 22 bits of parity information and is stuffed into 3 bytes.
/// The two unused bit are set to 1.
/// The ECC can correct single bit errors in a 256-byte page of data. Thus, two
/// such ECC blocks are used on a 512-byte NAND page.
///
///
///
/// Charles Manning, whoever you are and wherever you work now, your algorithm-writing
/// skills are impressive, but I desperately hope that the rest of the code you wrote
/// for Toby Churchill Ltd and Brightstar Engineering was better documented and easier
/// to work out than this.

pub fn calc_ecc_256<T: AsRef<[u8]>>(data: T) -> Ecc {
    debug_assert!(data.as_ref().len() == 256);

    let mut column_parity = 0xFF;

    let mut line_parity = 0xFF;
    let mut line_parity_prime = 0xFF;
    for (index, i) in data.as_ref().iter().enumerate() {
        for (bit_index, bit) in (0u8..8).map(|e| (e, i & (1 << e) != 0)) {
            if bit {
                let interleaved = (morton_encode([bit_index, !bit_index]) << 2) as u8;
                column_parity ^= interleaved | 1;
            }
        }
        //column_parity ^= COLUMN_PARITY_TABLE[*i as usize];
        if (i.count_ones() % 2) != 0 {
            line_parity ^= index as u8;
            line_parity_prime ^= !index as u8;
        }
    }

    let interleaved = &morton_encode([line_parity, line_parity_prime]).to_le_bytes();
    column_parity |= 3;

    (interleaved[0], interleaved[1], column_parity)
}

pub fn calc_ecc_512<T: AsRef<[u8]>>(data: T) -> (Ecc, Ecc) {
    debug_assert!(data.as_ref().len() == 512);

    let first = calc_ecc_256(&data.as_ref()[..256]);
    let second = calc_ecc_256(&data.as_ref()[256..]);

    (first, second)
}

#[derive(Debug)]
pub enum EccResult256 {
    NoError,
    CorrectedData,
    CorrectedEcc(Ecc),
    Failed,
}

pub fn correct_ecc_256<T: AsMut<[u8]>>(mut data: T, ecc: Ecc) -> EccResult256 {
    debug_assert!(data.as_mut().len() == 256);

    let calculated_ecc = calc_ecc_256(data.as_mut());

    let (d0, d1, d2) = (
        ecc.0 ^ calculated_ecc.0,
        ecc.1 ^ calculated_ecc.1,
        ecc.2 ^ calculated_ecc.2,
    );

    if d0 | d1 | d2 == 0 {
        return EccResult256::NoError;
    }

    if ((d0 ^ (d0 >> 1)) & 0x55) == 0x55
        && ((d1 ^ (d1 >> 1)) & 0x55) == 0x55
        && ((d2 ^ (d2 >> 1)) & 0x54) == 0x54
    {
        let byte = morton_decode::<u8, 2>(((d1 as u16) << 8) | (d0 as u16))[0];
        let bit = morton_decode::<u8, 2>(d2.into())[0] >> 1;

        data.as_mut()[byte as usize] ^= 1 << bit;

        return EccResult256::CorrectedData;
    }

    if d0.count_ones() + d1.count_ones() + d2.count_ones() == 1 {
        return EccResult256::CorrectedEcc(calculated_ecc);
    }

    EccResult256::Failed
}

pub enum EccResult {
    NoError,
    Corrected,
    Failed,
}

pub fn correct_ecc_512<T: AsMut<[u8]>>(mut data: T, eccs: (Ecc, Ecc)) -> EccResult {
    debug_assert!(data.as_mut().len() == 512);

    let (first, second) = eccs;

    let state = match correct_ecc_256(&mut data.as_mut()[..256], first) {
        EccResult256::NoError => EccResult::NoError,
        EccResult256::Failed => return EccResult::Failed,
        _ => EccResult::Corrected,
    };

    match correct_ecc_256(&mut data.as_mut()[256..], second) {
        EccResult256::NoError => state,
        EccResult256::Failed => EccResult::Failed,
        _ => EccResult::Corrected,
    }
}

#[binrw]
#[br(map(|x: u8| {
    match x.count_zeros() {
        0 => Self::Good,
        1 => Self::OneBitError(x),
        _ => Self::Bad(x),
    }
}))]
#[bw(map(|x: &Self| {
    match *x {
        BadBlockIndicator::Good => 0,
        BadBlockIndicator::OneBitError(n) => n,
        BadBlockIndicator::Bad(n) => n
    }
}))]
pub enum BadBlockIndicator {
    Good,
    OneBitError(u8),
    Bad(u8),
}

#[binrw]
pub struct Spare {
    #[brw(pad_after(2))]
    sa_block_data: (u8, u8, u8),
    #[brw(pad_after(2))]
    bad: BadBlockIndicator,
    #[brw(pad_after(2))]
    second: Ecc,
    first: Ecc,
}

impl Spare {
    pub const SIZE: usize = 0x10;

    pub fn read_from_buf(buf: &[u8]) -> BinResult<Self> {
        if buf.len() != Self::SIZE {
            return Err(binrw::Error::AssertFail {
                pos: 0,
                message: format!(
                    "incorrect size (got {} bytes, expected {})",
                    buf.len(),
                    Self::SIZE
                ),
            });
        }

        let mut cursor = Cursor::new(buf);
        <_>::read_be(&mut cursor)
    }
}

pub struct SpareData {
    pub sa_block: u8,
    pub bad: bool,
    pub first: Ecc,
    pub second: Ecc,
}

impl From<Spare> for SpareData {
    fn from(spare: Spare) -> Self {
        let sa_block = if spare.sa_block_data.0 != spare.sa_block_data.1 {
            spare.sa_block_data.2
        } else {
            spare.sa_block_data.0
        };
        let bad = matches!(spare.bad, BadBlockIndicator::Bad(_));
        Self {
            sa_block,
            bad,
            first: spare.first,
            second: spare.second,
        }
    }
}
