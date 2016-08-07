#![cfg_attr(test, feature(test))]
#![feature(trace_macros)]
#![recursion_limit="1000"]

use std::fmt;
use std::mem;
use std::ptr;

trace_macros!(false);

macro_rules! read {
    ([u8; $len:expr], $slice:expr, $index:expr) => {
        unsafe {
            debug_assert!($slice.len() >= $index + $len);
            let ret: [u8; $len] = mem::uninitialized();
            ptr::copy_nonoverlapping($slice.as_ptr().offset($index), &ret[0]);
            ret
        }
    };

    ($ty:ty, $slice:expr, $index:expr) => {
        unsafe {
            debug_assert!($slice.len() >= $index + mem::size_of::<$ty>());
            ptr::read($slice.as_ptr().offset($index) as *const u8 as *const $ty).to_be()
        }
    };
}

#[derive(Debug)]
pub enum Error {
    TooShort,
    BadVersion,
}

pub struct Packet<'bytes> {
    raw: &'bytes [u8],
}

impl<'bytes> Packet<'bytes> {
    pub fn from_bytes(raw: &'bytes [u8]) -> Result<Packet<'bytes>, Error> {
        if raw.len() < 20 {
            return Err(Error::TooShort);
        }

        let version = read!(u16, &raw, 0);

        if version != 9 {
            return Err(Error::BadVersion);
        }

        Ok(Packet { raw: raw })
    }

    pub fn header(&self) -> Header<'bytes> {
        Header { raw: &self.raw[..20] }
    }

    pub fn flowsets(&self) -> FlowSetIter<'bytes> {
        FlowSetIter { raw: &self.raw[20..] }
    }
}

pub struct Header<'bytes> {
    raw: &'bytes [u8],
}

impl<'bytes> Header<'bytes> {

    /// Version of Flow Record format exported in this packet.  The
    /// value of this field is 9 for the current version.
    pub fn version(&self) -> u16 {
        read!(u16, &self.raw, 0)
    }

    /// The total number of records in the Export Packet, which is the
    /// sum of Options FlowSet records, Template FlowSet records, and
    /// Data FlowSet records.
    pub fn count(&self) -> u16 {
        read!(u16, &self.raw, 2)
    }

    /// Time in milliseconds since this device was first booted.
    pub fn sys_uptime(&self) -> u32 {
        read!(u32, &self.raw, 4)
    }

    /// Time in seconds since 0000 UTC 1970, at which the Export Packet
    /// leaves the Exporter.
    pub fn seconds(&self) -> u32 {
        read!(u32, &self.raw, 8)
    }

    /// Incremental sequence counter of all Export Packets sent from
    /// the current Observation Domain by the Exporter.  This value
    /// MUST be cumulative, and SHOULD be used by the Collector to
    /// identify whether any Export Packets have been missed.
    pub fn seq_num(&self) -> u32 {
        read!(u32, &self.raw, 12)
    }

    /// A 32-bit value that identifies the Exporter Observation Domain.
    /// NetFlow Collectors SHOULD use the combination of the source IP
    /// address and the Source ID field to separate different export
    /// streams originating from the same Exporter.
    pub fn source_id(&self) -> u32 {
        read!(u32, &self.raw, 16)
    }
}

pub enum FlowSet<'packet> {
    DataTemplates(DataTemplateIter<'packet>),
    OptionsTemplates(OptionsTemplateIter<'packet>),
    DataRecords(DataRecords<'packet>),
    // OptionsTemplate(OptionsTemplateFS<'packet>),
    Other(Other<'packet>),
}

pub struct DataRecords<'bytes> {
    pub template_id: u16,
    pub raw: &'bytes [u8],
}
pub struct Other<'bytes> {
    pub flowset_id: u16,
    pub raw: &'bytes [u8],
}
// DATA
#[derive(Clone)]
pub struct DataTemplateIter<'bytes> {
    pub raw: &'bytes [u8],
}
impl<'bytes> Iterator for DataTemplateIter<'bytes> {
    type Item = DataTemplate<'bytes>;
    fn next(&mut self) -> Option<DataTemplate<'bytes>> {
        if self.raw.len() < 8 {
            return None;
        }

        let template_id = read!(u16, &self.raw, 0);
        let field_count = read!(u16, &self.raw, 2);
        let length = field_count as usize * 4 + 4;

        if self.raw.len() < length {
            return None;
        }

        let ret = DataTemplate {
            template_id: template_id,
            field_count: field_count,
            fields: TemplateFieldIter {
                raw: &self.raw[4..length],
            },
        };
        self.raw = &self.raw[length..];
        Some(ret)
    }
}

pub struct DataTemplate<'fields> {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: TemplateFieldIter<'fields>,
}
impl<'fields> DataTemplate<'fields> {
    pub fn build_extractor(&self) -> FlowRecordExtractor {
        FlowRecordExtractor::new(&self.fields, 0)
    }
}

#[derive(Clone)]
pub struct TemplateFieldIter<'bytes> {
    /// Where the record fields in a flow set begin. For flow records, this is always 0,
    /// for options records this starts after the scope data.
    pub raw: &'bytes [u8],
}
impl<'bytes> Iterator for TemplateFieldIter<'bytes> {
    type Item = (usize, TemplateField);
    fn next(&mut self) -> Option<(usize, TemplateField)> {
        debug_assert!(self.raw.len() % 4 == 0);

        if self.raw.len() < 4 {
            return None;
        }

        let field_type = read!(u16, &self.raw, 0);
        let field_len = read!(u16, &self.raw, 2);
        self.raw = &self.raw[4..];
        Some((field_len as usize, TemplateField::new(field_type, field_len)))
    }
}

// OPTIONS
#[derive(Clone)]
pub struct OptionsTemplateIter<'bytes> {
    pub raw: &'bytes [u8],
}
impl<'bytes> Iterator for OptionsTemplateIter<'bytes> {
    type Item = OptionsTemplate<'bytes>;
    fn next(&mut self) -> Option<OptionsTemplate<'bytes>> {
        if self.raw.len() < 6 {
            return None;
        }

        let template_id = read!(u16, &self.raw, 0);
        let option_scope_length = read!(u16, &self.raw, 2);
        let option_length = read!(u16, &self.raw, 4);
        let length = option_scope_length as usize + option_length as usize + 6;
        let &(scopes, options) = &self.raw[6..].split_at(option_scope_length as usize);

        if self.raw.len() < length {
            return None;
        }

        let ret = OptionsTemplate {
            template_id: template_id,
            option_scope_length: option_scope_length,
            option_length: option_length,
            scopes: ScopeIter { raw: scopes },
            fields: TemplateFieldIter {
                raw: &options[..option_length as usize],
            },
        };
        self.raw = &self.raw[length..];
        Some(ret)
    }
}

pub struct OptionsTemplate<'fields> {
    pub template_id: u16,
    pub option_scope_length: u16,
    pub option_length: u16,
    pub scopes: ScopeIter<'fields>,
    pub fields: TemplateFieldIter<'fields>,
}
impl<'fields> OptionsTemplate<'fields> {
    pub fn build_extractor(&self) -> FlowRecordExtractor {
        FlowRecordExtractor::new(&self.fields, self.option_scope_length as usize)
    }
}

#[derive(Clone)]
pub struct ScopeIter<'bytes> {
    raw: &'bytes [u8],
}
impl<'bytes> Iterator for ScopeIter<'bytes> {
    type Item = (u16, Scope);
    fn next(&mut self) -> Option<(u16, Scope)> {
        debug_assert!(self.raw.len() % 4 == 0);

        if self.raw.len() < 4 {
            return None;
        }

        let scope_id = read!(u16, &self.raw, 0);
        let scope_len = read!(u16, &self.raw, 2);
        self.raw = &self.raw[4..];
        Some((scope_len, Scope::new(scope_id, scope_len)))
    }
}

#[derive(Debug)]
pub enum Scope {
    System(u16),
    Interface(u16),
    Linecard(u16),
    Cache(u16),
    Template(u16),
    Unknown(u16),
}

impl Scope {
    pub fn new(id: u16, len: u16) -> Scope {
        match id {
            1 => Scope::System(len),
            2 => Scope::Interface(len),
            3 => Scope::Linecard(len),
            4 => Scope::Cache(len),
            5 => Scope::Template(len),
            _ => Scope::Unknown(len),
        }
    }
}

macro_rules! cond_read_bytes {
    ($src:expr, $dst:ident, $len:expr, 1, $ty:ident ) => {
        if $len == 1 {
            $dst = ptr::read($src.as_ptr() as *const u8).to_be() as $ty;
        }
    };

    ($src:expr, $dst:ident, $len:expr, 2, $ty:ident ) => {
        if $len == 2 {
            $dst = ptr::read($src.as_ptr() as *const u16).to_be() as $ty;
        }
    };

    ($src:expr, $dst:ident, $len:expr, 4, $ty:ident ) => {
        if $len == 4 {
            $dst = ptr::read($src.as_ptr() as *const u32).to_be() as $ty;
        }
    };

    ($src:expr, $dst:ident, $len:expr, 8, $ty:ident ) => {
        if $len == 8 {
            $dst = ptr::read($src.as_ptr() as *const u64).to_be() as $ty;
        }
    };
}

macro_rules! field_getter {
    (subTemplateMultiList, $fun:ident, $sizes:tt, $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<&'bytes [u8]> {
            self.offsets.$fun.map(|offset| {
                &self.raw[(offset)..(self.lengths.$fun as usize + offset)]
            })
        }
    };

    (subTemplateList, $fun:ident, $sizes:tt, $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<&'bytes [u8]> {
            self.offsets.$fun.map(|offset| {
                &self.raw[(offset )..(self.lengths.$fun as usize + offset)]
            })
        }
    };

    (basicList, $fun:ident, $sizes:tt, $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<&'bytes [u8]> {
            self.offsets.$fun.map(|offset| {
                &self.raw[(offset )..(self.lengths.$fun as usize + offset)]
            })
        }
    };

    (octetArray, $fun:ident, $sizes:tt, $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<&'bytes [u8]> {
            self.offsets.$fun.map(|offset| {
                &self.raw[(offset )..(self.lengths.$fun as usize + offset)]
            })
        }
    };

    (string, $fun:ident, $sizes:tt, $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<&'bytes [u8]> {
            self.offsets.$fun.map(|offset| {
                &self.raw[(offset )..(self.lengths.$fun as usize + offset)]
            })
        }
    };

    // fixed-length
    ([u8; $len:expr], $fun:ident, (), $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<[u8; $len]> {
            self.offsets.$fun.map(|offset| {
                debug_assert!(self.raw.len() >= (offset ) + $len);
                unsafe {
                    let ptr = self.raw.as_ptr().offset(offset as isize);
                    ptr::read(ptr as *const _)
                }
            })
        }
    };

    (f64, $fun:ident, (), $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<f64> {
            self.offsets.$fun.map(|offset| {
                debug_assert!(self.raw.len() >= (offset ) + mem::size_of::<f64>());
                unsafe {
                    ptr::read(self.raw.as_ptr().offset(offset as isize) as *const f64)
                }
            })
        }
    };

    (bool, $fun:ident, (), $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<bool> {
            self.offsets.$fun.map(|offset| {
                self.raw[offset] > 0
            })
        }
    };

    // unsigned integers
    ($ty:ty, $fun:ident, (), $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<$ty> {
            self.offsets.$fun.map(|offset| {
                debug_assert!(self.raw.len() >= (offset ) + mem::size_of::<$ty>());
                unsafe {
                    let mut ret: $ty = mem::uninitialized();
                    ptr::copy_nonoverlapping(&self.raw[(offset )],
                                             &mut ret as *mut _ as *mut u8,
                                             mem::size_of::<$ty>());

                    if cfg!(target_endian = "little") {
                        ret.swap_bytes()
                    } else {
                        ret
                    }
                }
            })
        }
    };

    // variable-length
    ($ty:ident, $fun:ident, ($($size:tt),*), $doc:meta) => {
        #[$doc]
        pub fn $fun(&self) -> Option<$ty> {
            self.offsets.$fun.map(|offset| {
                let mut ret: $ty = 0;
                debug_assert!(self.lengths.$fun > 0);
                unsafe {
                    $(cond_read_bytes!(&self.raw[(offset )..], ret, self.lengths.$fun as usize, $size, $ty);)*
                }
                ret
            })
        }
    };
}

// Necessary, see https://github.com/rust-lang/rfcs/issues/1144
macro_rules! size_of {
    (u8) => {1};
    (bool) => {1};
    (u16) => {2};
    (u32) => {4};
    (u64) => {8};
    (f32) => {4};
    (f64) => {8};
    ([u8; $len:expr]) => {$len};
}


macro_rules! def_length_struct {
    // retain elements with non-empty lengths list
    (@filter ($($accepted:tt)*) ($name:ident, string, $lengths:tt) $($tail:tt)* ) => {
        def_length_struct!(@filter ($($accepted)* $name) $($tail)* );
    };

    (@filter ($($accepted:tt)*) ($name:ident, octetArray, $lengths:tt) $($tail:tt)* ) => {
        def_length_struct!(@filter ($($accepted)* $name) $($tail)* );
    };

    (@filter ($($accepted:tt)*) ($name:ident, basicList, $lengths:tt) $($tail:tt)* ) => {
        def_length_struct!(@filter ($($accepted)* $name) $($tail)* );
    };

    (@filter ($($accepted:tt)*) ($name:ident, subTemplateList, $lengths:tt) $($tail:tt)* ) => {
        def_length_struct!(@filter ($($accepted)* $name) $($tail)* );
    };

    (@filter ($($accepted:tt)*) ($name:ident, subTemplateMultiList, $lengths:tt) $($tail:tt)* ) => {
        def_length_struct!(@filter ($($accepted)* $name) $($tail)* );
    };

    (@filter ($($accepted:tt)*) ($name:ident, string, $lengths:tt) $($tail:tt)* ) => {
        def_length_struct!(@filter ($($accepted)* $name) $($tail)* );
    };

    (@filter $accepted:tt ($name:ident, $ty:ty,  ()) $($tail:tt)* ) => {
        // remove elements with empty length field
        def_length_struct!(@filter $accepted $($tail)* );
    };

    (@filter ($($accepted:tt)*) ($name:ident, $ty:ty, $lengths:tt) $($tail:tt)* ) => {
        // retain elements with non-empty lengths list
        def_length_struct!(@filter ($($accepted)* $name) $($tail)* );
    };

    (@filter ($($accepted:ident)*) ) => {
        #[derive(Debug, Default)]
        pub struct RecordFieldLengths {
            $(pub $accepted: usize, )*

        }
    };

    ($head:tt $($tail:tt)*) => {
        def_length_struct!(@filter () $head $($tail)*);
    };
}

macro_rules! field_match_len {
    ($source_len:ident, basicList, $camel:ident, ()) => {
        return $camel;
    };

    ($source_len:ident, subTemplateList, $camel:ident, ()) => {
        return $camel;
    };

    ($source_len:ident, subTemplateMultiList, $camel:ident, ()) => {
        return $camel;
    };

    ($source_len:ident, string, $camel:ident, ()) => {
        return $camel;
    };

    ($source_len:ident, octetArray, $camel:ident, ()) => {
        return $camel;
    };

    ($source_len:ident, $ty:tt, $camel:ident, ()) => {
        if $source_len == size_of!($ty) {
            return $camel;
        }
    };

    ($source_len:ident, $ty:tt, $camel:ident, ($( $size:expr ),*)) => {
        $(
            if $source_len == $size {
                return $camel;
            }
        )*
    };
}

macro_rules! field_match {
    ($source_id:ident, $source_len:ident, $id:expr, $camel:ident, $ty:tt, $sizes:tt) => {
        if $source_id == $id {
            field_match_len!($source_len, $ty, $camel, $sizes);
        }
    };
}

macro_rules! set_lengths {
    (@filter $field:ident, $strukt:expr, $len:ident, ($($accepted:tt)*) (string, $camel:ident, $snake:ident, $lengths:tt) $($tail:tt)* ) => {
        // retain elements with non-empty lengths list
        set_lengths!(@filter $field, $strukt, $len, ($($accepted)* (string, $camel, $snake, $lengths)) $($tail)* );
    };

    (@filter $field:ident, $strukt:expr, $len:ident, ($($accepted:tt)*) (octetArray, $camel:ident, $snake:ident, $lengths:tt) $($tail:tt)* ) => {
        // retain elements with non-empty lengths list
        set_lengths!(@filter $field, $strukt, $len, ($($accepted)* (octetArray, $camel, $snake, $lengths)) $($tail)* );
    };

    (@filter $field:ident, $strukt:expr, $len:ident, ($($accepted:tt)*) (basicList, $camel:ident, $snake:ident, $lengths:tt) $($tail:tt)* ) => {
        // retain elements with non-empty lengths list
        set_lengths!(@filter $field, $strukt, $len, ($($accepted)* (basicList, $camel, $snake, $lengths)) $($tail)* );
    };

    (@filter $field:ident, $strukt:expr, $len:ident, ($($accepted:tt)*) (subTemplateList, $camel:ident, $snake:ident, $lengths:tt) $($tail:tt)* ) => {
        // retain elements with non-empty lengths list
        set_lengths!(@filter $field, $strukt, $len, ($($accepted)* (subTemplateList, $camel, $snake, $lengths)) $($tail)* );
    };

    (@filter $field:ident, $strukt:expr, $len:ident, ($($accepted:tt)*) (subTemplateMultiList, $camel:ident, $snake:ident, $lengths:tt) $($tail:tt)* ) => {
        // retain elements with non-empty lengths list
        set_lengths!(@filter $field, $strukt, $len, ($($accepted)* (subTemplateMultiList, $camel, $snake, $lengths)) $($tail)* );
    };



    (@filter $field:ident, $strukt:expr, $len:ident, $accepted:tt ($ty:ty, $camel:ident, $snake:ident, ()) $($tail:tt)* ) => {
        // remove elements with empty length field
        set_lengths!(@filter $field, $strukt, $len, $accepted $($tail)* );
    };

    (@filter $field:ident, $strukt:expr, $len:ident, ($($accepted:tt)*) ($ty:ty, $camel:ident, $snake:ident, $lengths:tt) $($tail:tt)* ) => {
        // retain elements with non-empty lengths list
        set_lengths!(@filter $field, $strukt, $len, ($($accepted)* ($ty, $camel, $snake, $lengths)) $($tail)* );
    };

    (@filter $field:ident, $strukt:expr, $len:ident, ( $( ($ty:ty, $camel:ident, $snake:ident, $lengths:tt) )* ) ) => {
        match $field {
            $($camel => { $strukt.$snake = $len; }, )*
            _ => (),
        }
    };

    ( $field:ident, $strukt:expr, $len:ident, $head:tt $($tail:tt)* ) => {
        set_lengths!(@filter $field, $strukt, $len, () $head $($tail)*);
    };
}

macro_rules! define_fields {
    {
        $( $id:expr => ($camel:ident, $snake:ident, $ty:tt, $sizes:tt, $doc:meta), )*
    } => {

        #[derive(Debug, PartialEq, Eq)]
        pub enum TemplateField {
            Unknown,
            $( $camel, )*
        }

        impl TemplateField {
            pub fn new(field_type: u16, field_len: u16) -> TemplateField {
                use TemplateField::*;
                $( field_match!(field_type, field_len, $id, $camel, $ty, $sizes); )*
                Unknown
            }

        }

        #[derive(Default)]
        struct RecordFieldOffsets {
            $( pub $snake: Option<usize>, )*
        }

        def_length_struct!( $( ($snake, $ty, $sizes) )* );

        #[derive(Default)]
        pub struct FlowRecordExtractor {
            record_size: usize,
            offsets: RecordFieldOffsets,
            lengths: RecordFieldLengths,
        }

        impl FlowRecordExtractor {

            pub fn new(fields: &TemplateFieldIter, start_offset: usize) -> FlowRecordExtractor {
                let mut ret: FlowRecordExtractor = Default::default();
                let mut offset = start_offset;

                for (len, field) in fields.clone() {
                    use TemplateField::*;

                    match field {
                        $( $camel => { ret.offsets.$snake = Some(offset)} )*
                        _ => ()
                    }

                    set_lengths!(field, ret.lengths, len, $( ($ty, $camel, $snake, $sizes) )* );
                    offset += len;
                }

                ret.record_size = offset;
                ret
            }

            pub fn records<'extractor, 'data>(&'extractor self, data: &'data DataRecords)
                                           -> RecordIter<'extractor, 'data>
            {
                RecordIter {
                    extractor: self,
                    raw: data.raw,
                }
            }
        }

        pub struct Record<'extractor, 'bytes> {
            offsets: &'extractor RecordFieldOffsets,
            lengths: &'extractor RecordFieldLengths,
            raw: &'bytes [u8],
        }

        impl<'extractor, 'bytes> Record<'extractor, 'bytes> {
            $( field_getter!($ty, $snake, $sizes, $doc); )*
        }

        impl<'extractor, 'bytes> fmt::Debug for Record<'extractor, 'bytes> {

            fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
                let debug_struct = &mut f.debug_struct("Record");
                $(
                    if let Some(val) = self.$snake() {
                        debug_struct.field(stringify!($snake), &val);
                    };
                )*
                debug_struct.finish()
            }

        }
    }
}

pub struct RecordIter<'extractor, 'bytes> {
    extractor: &'extractor FlowRecordExtractor,
    raw: &'bytes [u8],
}

impl<'extractor, 'bytes> Iterator for RecordIter<'extractor, 'bytes> {
    type Item = Record<'extractor, 'bytes>;

    fn next(&mut self) -> Option<Record<'extractor, 'bytes>> {
        if self.raw.len() < self.extractor.record_size {
            return None;
        }

        let ret = &self.raw[..self.extractor.record_size];
        self.raw = &self.raw[self.extractor.record_size..];
        Some(Record {
            offsets: &self.extractor.offsets,
            lengths: &self.extractor.lengths,
            raw: ret,
        })
    }
}

pub struct FlowSetIter<'bytes> {
    raw: &'bytes [u8],
}

impl<'bytes> Iterator for FlowSetIter<'bytes> {
    type Item = FlowSet<'bytes>;
    fn next(&mut self) -> Option<FlowSet<'bytes>> {
        if self.raw.len() < 4 {
            return None;
        }

        let flowset_id = read!(u16, &self.raw, 0);
        let length = read!(u16, &self.raw, 2) as usize;

        if self.raw.len() < length {
            return None;
        }

        let ret = match flowset_id {
            0 => FlowSet::DataTemplates(DataTemplateIter { raw: &self.raw[4..length] }),
            1 => FlowSet::OptionsTemplates(OptionsTemplateIter { raw: &self.raw[4..length] }),
            n @ 2...255 => {
                FlowSet::Other(Other {
                    flowset_id: n,
                    raw: &self.raw[4..length],
                })
            }
            n => {
                FlowSet::DataRecords(DataRecords {
                    template_id: n,
                    raw: &self.raw[4..length],
                })
            }
        };
        self.raw = &self.raw[length..];
        Some(ret)
    }
}

include!("fields.rs");

#[cfg(test)]
mod tests;

