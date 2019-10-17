#[inline]
pub fn slice_to_u32_be(slice: &[u8]) -> u32 {
    assert_eq!(slice.len(), 4);
    (slice[0] as u32) << 3*8 |
    (slice[1] as u32) << 2*8 |
    (slice[2] as u32) << 1*8 |
    (slice[3] as u32) << 0*8
}

#[inline]
pub fn u32_to_array_be(val: u32) -> [u8; 4] {
    [
        ((val >> 3*8) & 0xff) as u8,
        ((val >> 2*8) & 0xff) as u8,
        ((val >> 1*8) & 0xff) as u8,
        ((val >> 0*8) & 0xff) as u8,
    ]
}

#[inline]
pub fn u16_to_array_le(val: u16) -> [u8; 2] {
    [
        ((val >> 0*8) & 0xff) as u8,
        ((val >> 1*8) & 0xff) as u8,
    ]
}
#[inline]
pub fn i16_to_array_le(val: i16) -> [u8; 2] {
    u16_to_array_le(val as u16)
}

#[inline]
pub fn slice_to_u16_le(slice: &[u8]) -> u16 {
    assert_eq!(slice.len(), 2);
    (slice[0] as u16) << 0*8 |
    (slice[1] as u16) << 1*8
}
#[inline]
pub fn slice_to_i16_le(slice: &[u8]) -> i16 {
    slice_to_u16_le(slice) as i16
}

#[inline]
pub fn slice_to_u32_le(slice: &[u8]) -> u32 {
    assert_eq!(slice.len(), 4);
    (slice[0] as u32) << 0*8 |
    (slice[1] as u32) << 1*8 |
    (slice[2] as u32) << 2*8 |
    (slice[3] as u32) << 3*8
}
#[inline]
pub fn slice_to_i32_le(slice: &[u8]) -> i32 {
    slice_to_u32_le(slice) as i32
}

#[inline]
pub fn u32_to_array_le(val: u32) -> [u8; 4] {
    [
        ((val >> 0*8) & 0xff) as u8,
        ((val >> 1*8) & 0xff) as u8,
        ((val >> 2*8) & 0xff) as u8,
        ((val >> 3*8) & 0xff) as u8,
    ]
}
#[inline]
pub fn i32_to_array_le(val: i32) -> [u8; 4] {
    u32_to_array_le(val as u32)
}

#[inline]
pub fn slice_to_u64_le(slice: &[u8]) -> u64 {
    assert_eq!(slice.len(), 8);
    (slice[0] as u64) << 0*8 |
    (slice[1] as u64) << 1*8 |
    (slice[2] as u64) << 2*8 |
    (slice[3] as u64) << 3*8 |
    (slice[4] as u64) << 4*8 |
    (slice[5] as u64) << 5*8 |
    (slice[6] as u64) << 6*8 |
    (slice[7] as u64) << 7*8
}
#[inline]
pub fn slice_to_i64_le(slice: &[u8]) -> i64 {
    slice_to_u64_le(slice) as i64
}

#[inline]
pub fn u64_to_array_le(val: u64) -> [u8; 8] {
    [
        ((val >> 0*8) & 0xff) as u8,
        ((val >> 1*8) & 0xff) as u8,
        ((val >> 2*8) & 0xff) as u8,
        ((val >> 3*8) & 0xff) as u8,
        ((val >> 4*8) & 0xff) as u8,
        ((val >> 5*8) & 0xff) as u8,
        ((val >> 6*8) & 0xff) as u8,
        ((val >> 7*8) & 0xff) as u8,
    ]
}
#[inline]
pub fn i64_to_array_le(val: i64) -> [u8; 8] {
    u64_to_array_le(val as u64)
}
