//! The declaration that gives a plan record its codec.
//!
//! A record is written once, as a list of fields and the kind each one is
//! encoded as, and the struct, the encoder, the decoder and the encoded size
//! all come from that single list. The plan crosses a process boundary, so an
//! encoder and a decoder that disagreed would not be caught: the reader would
//! accept the bytes and mean something else by them. Deriving all of them from
//! one declaration leaves that disagreement impossible to write.
//!
//! A field whose kind is one of the padded aliases below carries the zero
//! bytes that keep the field after it at its natural offset. The padding is
//! written as zero and skipped when read.

/// A `u8` followed by three bytes of padding.
pub type U8Pad3 = u8;

/// A `u32` followed by four bytes of padding.
pub type U32Pad4 = u32;

/// An `i32` followed by four bytes of padding.
pub type I32Pad4 = i32;

/// Defines a fixed-size plan record together with its codec.
macro_rules! record {
    (@size bool) => { 1 };
    (@size u8) => { 1 };
    (@size u32) => { 4 };
    (@size i32) => { 4 };
    (@size u64) => { 8 };
    (@size i64) => { 8 };
    (@size Str) => { Str::SIZE };
    (@size U8Pad3) => { 1 + 3 };
    (@size U32Pad4) => { 4 + 4 };
    (@size I32Pad4) => { 4 + 4 };

    (@put $w:ident, bool, $value:expr) => { $w.bool($value) };
    (@put $w:ident, u8, $value:expr) => { $w.u8($value) };
    (@put $w:ident, u32, $value:expr) => { $w.u32($value) };
    (@put $w:ident, i32, $value:expr) => { $w.i32($value) };
    (@put $w:ident, u64, $value:expr) => { $w.u64($value) };
    (@put $w:ident, i64, $value:expr) => { $w.i64($value) };
    (@put $w:ident, Str, $value:expr) => { $w.str($value) };
    (@put $w:ident, U8Pad3, $value:expr) => {{
        $w.u8($value);
        $w.u8(0);
        $w.u8(0);
        $w.u8(0);
    }};
    (@put $w:ident, U32Pad4, $value:expr) => {{
        $w.u32($value);
        $w.u32(0);
    }};
    (@put $w:ident, I32Pad4, $value:expr) => {{
        $w.i32($value);
        $w.i32(0);
    }};

    (@get $r:ident, bool) => { $r.bool()? };
    (@get $r:ident, u8) => { $r.u8()? };
    (@get $r:ident, u32) => { $r.u32()? };
    (@get $r:ident, i32) => { $r.i32()? };
    (@get $r:ident, u64) => { $r.u64()? };
    (@get $r:ident, i64) => { $r.i64()? };
    (@get $r:ident, Str) => { $r.str()? };
    (@get $r:ident, U8Pad3) => {{
        let value = $r.u8()?;
        $r.u8()?;
        $r.u8()?;
        $r.u8()?;
        value
    }};
    (@get $r:ident, U32Pad4) => {{
        let value = $r.u32()?;
        $r.u32()?;
        value
    }};
    (@get $r:ident, I32Pad4) => {{
        let value = $r.i32()?;
        $r.i32()?;
        value
    }};

    (
        $(#[$record_meta:meta])*
        pub struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field:ident: $kind:ident,
            )*
        }
    ) => {
        $(#[$record_meta])*
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name {
            $(
                $(#[$field_meta])*
                pub $field: $kind,
            )*
        }

        impl $name {
            /// Encoded size in bytes.
            #[allow(clippy::identity_op)]
            pub const SIZE: usize = 0 $(+ record!(@size $kind))*;

            /// Appends this record, in the order the fields are declared.
            pub fn encode(&self, w: &mut Writer) {
                $(record!(@put w, $kind, self.$field);)*
            }

            /// Reads one record.
            pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
                $(let $field = record!(@get r, $kind);)*
                Ok(Self { $($field,)* })
            }
        }
    };
}
