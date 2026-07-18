use crate::array::*;
use crate::heap::*;
use crate::string::*;
use crate::value::*;
use std::fmt::{self, Write};

/// A sink used while the VM converts values into strings.
///
/// Ordinary [`String`] sinks preserve the upstream unbounded behavior. The
/// runtime can instead use [`ScriptStringBuffer`] to stop a script-created
/// string before it grows past the host-selected limit.
pub trait ScriptStringSink: Write {
    fn is_full(&self) -> bool;

    fn append_str(&mut self, value: &str) {
        let _ = self.write_str(value);
    }

    fn append_char(&mut self, value: char) {
        let _ = self.write_char(value);
    }
}

impl ScriptStringSink for String {
    fn is_full(&self) -> bool {
        false
    }
}

/// A string builder that records a limit hit without allocating beyond its
/// configured logical byte length.
pub struct ScriptStringBuffer {
    value: String,
    maximum_bytes: Option<usize>,
    full: bool,
}

impl ScriptStringBuffer {
    fn new(value: String, maximum_bytes: Option<usize>) -> Self {
        Self {
            value,
            maximum_bytes,
            full: false,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    fn into_parts(self) -> (String, bool) {
        (self.value, self.full)
    }

    fn reserve_append(&mut self, additional_bytes: usize) -> Result<(), fmt::Error> {
        if self.full {
            return Err(fmt::Error);
        }
        let Some(next_len) = self.value.len().checked_add(additional_bytes) else {
            self.full = true;
            return Err(fmt::Error);
        };
        if self
            .maximum_bytes
            .is_some_and(|maximum| next_len > maximum)
        {
            self.full = true;
            return Err(fmt::Error);
        }
        if self.value.try_reserve(additional_bytes).is_err() {
            self.full = true;
            return Err(fmt::Error);
        }
        Ok(())
    }
}

impl Write for ScriptStringBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.reserve_append(value.len())?;
        self.value.push_str(value);
        Ok(())
    }

    fn write_char(&mut self, value: char) -> fmt::Result {
        let mut encoded = [0; 4];
        self.write_str(value.encode_utf8(&mut encoded))
    }
}

impl ScriptStringSink for ScriptStringBuffer {
    fn is_full(&self) -> bool {
        self.full
    }
}

impl ScriptHeap {
    // Strings

    /// Sets a maximum length for newly constructed script strings.
    ///
    /// `None` preserves the inherited VM behavior. A limit applies only to
    /// string construction after this call; existing heap strings remain
    /// valid so a host can safely lower a limit between completed runs.
    pub fn set_max_string_bytes(&mut self, maximum_bytes: Option<usize>) {
        self.max_string_bytes = maximum_bytes;
        self.string_limit_exceeded = false;
    }

    /// Returns and clears a pending bounded-string construction failure.
    pub fn take_string_limit_exceeded(&mut self) -> bool {
        std::mem::take(&mut self.string_limit_exceeded)
    }

    pub fn string_mut_self_with<R, F: FnOnce(&mut Self, &str) -> R>(
        &mut self,
        value: ScriptValue,
        cb: F,
    ) -> Option<R> {
        if let Some(s) = value.as_string() {
            if let Some(s) = &self.strings[s] {
                let s = s.string.clone();
                let r = cb(self, &s.0);
                return Some(r);
            } else {
                return None;
            }
        }
        if let Some(r) = value.as_inline_string(|s| cb(self, s)) {
            return Some(r);
        }
        None
    }

    pub fn string_with<R, F: FnOnce(&Self, &str) -> R>(
        &self,
        value: ScriptValue,
        cb: F,
    ) -> Option<R> {
        if let Some(s) = value.as_string() {
            if let Some(s) = &self.strings[s] {
                let r = cb(self, &s.string.0);
                return Some(r);
            } else {
                return None;
            }
        }
        if let Some(r) = value.as_inline_string(|s| cb(self, s)) {
            return Some(r);
        }
        None
    }

    pub fn new_string_from_str(&mut self, value: &str) -> ScriptValue {
        if self.max_string_bytes.is_none() {
            if let Some(value) = ScriptValue::from_inline_string(value) {
                return value;
            }
        }
        self.new_bounded_string_with(|_, out| {
            out.append_str(value);
        })
    }

    /// Builds a temporary host string with the inherited unbounded callback
    /// contract. Runtime-owned native operations must use
    /// [`Self::temp_bounded_string_with`] instead.
    pub fn temp_string_with<R, F: FnOnce(&mut Self, &mut String) -> R>(
        &mut self,
        cb: F,
    ) -> R {
        let mut out = self.take_string_buffer();
        let r = cb(self, &mut out);
        self.recycle_string(out);
        r
    }

    /// Builds a temporary string through the configured per-string limit.
    pub fn temp_bounded_string_with<R, F: FnOnce(&mut Self, &mut ScriptStringBuffer) -> R>(
        &mut self,
        cb: F,
    ) -> R {
        let mut out = self.new_string_buffer();
        let r = cb(self, &mut out);
        self.recycle_string_buffer(out);
        r
    }

    /// Builds a host string with the inherited unbounded callback contract.
    /// Runtime-owned native operations must use
    /// [`Self::new_bounded_string_with`] instead.
    pub fn new_string_with<F: FnOnce(&mut Self, &mut String)>(&mut self, cb: F) -> ScriptValue {
        let mut out = self.take_string_buffer();
        cb(self, &mut out);
        self.intern_or_store_string(out)
    }

    /// Builds a script string through the configured per-string limit.
    pub fn new_bounded_string_with<F: FnOnce(&mut Self, &mut ScriptStringBuffer)>(
        &mut self,
        cb: F,
    ) -> ScriptValue {
        let mut out = self.new_string_buffer();
        cb(self, &mut out);
        let (out, exceeded) = out.into_parts();
        if exceeded {
            self.string_limit_exceeded = true;
            self.recycle_string(out);
            return NIL;
        }
        self.intern_or_store_string(out)
    }

    /// Takes an owned String and either interns it, reuses an existing interned value, or stores it as a new string.
    /// The String is consumed and may be returned to the reuse pool.
    pub fn intern_or_store_string(&mut self, out: String) -> ScriptValue {
        if self
            .max_string_bytes
            .is_some_and(|maximum| out.len() > maximum)
        {
            self.string_limit_exceeded = true;
            self.recycle_string(out);
            return NIL;
        }
        if let Some(v) = ScriptValue::from_inline_string(&out) {
            self.recycle_string(out);
            return v;
        }

        // check intern table
        if let Some(index) = self.string_intern.get(&out).copied() {
            self.recycle_string(out);
            return index.into();
        }

        // fetch a free string
        if let Some(str) = self.strings_free.pop() {
            // str already has the correct generation from gc.rs sweep
            let out = ScriptRcString::new(out);
            self.strings[str] = Some(ScriptStringData {
                tag: Default::default(),
                string: out.clone(),
            });
            self.string_intern.insert(out, str);
            str
        } else {
            let out = ScriptRcString::new(out);
            let index = self.strings.len();
            self.strings.push(Some(ScriptStringData {
                tag: Default::default(),
                string: out.clone(),
            }));
            // New slot starts at generation 0
            let ret = ScriptString::new(index as _, crate::value::GENERATION_ZERO);
            self.string_intern.insert(out, ret);
            ret
        }
        .into()
    }

    pub fn check_intern_string(&self, value: &str) -> Option<ScriptValue> {
        if self
            .max_string_bytes
            .is_some_and(|maximum| value.len() > maximum)
        {
            return None;
        }
        if let Some(v) = ScriptValue::from_inline_string(&value) {
            Some(v)
        } else if let Some(idx) = self.string_intern.get(value) {
            Some((*idx).into())
        } else {
            None
        }
    }

    pub fn string(&self, ptr: ScriptString) -> &str {
        if let Some(s) = &self.strings[ptr] {
            &s.string.0
        } else {
            ""
        }
    }

    pub fn string_to_bytes_array(&mut self, v: ScriptValue) -> ScriptArray {
        let arr = self.new_array();
        if v.as_inline_string(|str| {
            let array = &mut self.arrays[arr];
            if let ScriptArrayStorage::U8(v) = &mut array.storage {
                v.clear();
                v.extend(str.as_bytes())
            } else {
                array.storage = ScriptArrayStorage::U8(str.as_bytes().into());
            }
        })
        .is_some()
        {
        } else if let Some(str) = v.as_string() {
            let array = &mut self.arrays[arr];
            let str = if let Some(s) = &self.strings[str] {
                &s.string.0
            } else {
                ""
            };
            if let ScriptArrayStorage::U8(v) = &mut array.storage {
                v.clear();
                v.extend(str.as_bytes())
            } else {
                array.storage = ScriptArrayStorage::U8(str.as_bytes().into());
            }
        }
        return arr;
    }

    pub fn string_to_chars_array(&mut self, v: ScriptValue) -> ScriptArray {
        let arr = self.new_array();
        if v.as_inline_string(|str| {
            let array = &mut self.arrays[arr];
            if let ScriptArrayStorage::U32(v) = &mut array.storage {
                v.clear();
                for c in str.chars() {
                    v.push(c as u32)
                }
            } else {
                array.storage = ScriptArrayStorage::U32(str.chars().map(|c| c as u32).collect());
            }
        })
        .is_some()
        {
        } else if let Some(str) = v.as_string() {
            let array = &mut self.arrays[arr];
            let str = if let Some(s) = &self.strings[str] {
                &s.string.0
            } else {
                ""
            };
            if let ScriptArrayStorage::U32(v) = &mut array.storage {
                v.clear();
                for c in str.chars() {
                    v.push(c as u32)
                }
            } else {
                array.storage = ScriptArrayStorage::U32(str.chars().map(|c| c as u32).collect());
            }
        }
        return arr;
    }

    pub fn cast_to_string<S: ScriptStringSink>(&self, v: ScriptValue, out: &mut S) {
        if v.as_inline_string(|s| out.append_str(s)).is_some() {
            return;
        }
        if let Some(v) = v.as_string() {
            let str = self.string(v);
            out.append_str(str);
            return;
        }
        if let Some(v) = v.as_f64() {
            write!(out, "{v}").ok();
            return;
        }
        if let Some(v) = v.as_u40() {
            write!(out, "{v}").ok();
            return;
        }
        if let Some(v) = v.as_bool() {
            write!(out, "{v}").ok();
            return;
        }
        if let Some(v) = v.as_id() {
            write!(out, "{v}").ok();
            return;
        }
        if v.is_nil() {
            return;
        }
        if let Some(v) = v.as_f32() {
            write!(out, "{v}").ok();
            return;
        }
        if let Some(v) = v.as_f16() {
            write!(out, "{v}").ok();
            return;
        }
        if let Some(v) = v.as_u32() {
            write!(out, "{v}").ok();
            return;
        }
        if let Some(v) = v.as_i32() {
            write!(out, "{v}").ok();
            return;
        }
        if let Some(_v) = v.as_object() {
            write!(out, "[ScriptObject]").ok();
            return;
        }
        if let Some(v) = v.as_color() {
            write!(out, "#{:08x}", v).ok();
            return;
        }
        if v.is_opcode() {
            write!(out, "[Opcode]").ok();
            return;
        }
        if v.is_err() {
            write!(out, "[Error:{}]", v).ok();
            return;
        }
        write!(out, "[Unknown]").ok();
    }

    fn new_string_buffer(&mut self) -> ScriptStringBuffer {
        let out = if let Some(out) = self.strings_reuse.pop() {
            if self
                .max_string_bytes
                .is_some_and(|maximum| out.capacity() > maximum)
            {
                String::new()
            } else {
                out
            }
        } else {
            String::new()
        };
        ScriptStringBuffer::new(out, self.max_string_bytes)
    }

    fn take_string_buffer(&mut self) -> String {
        self.strings_reuse.pop().unwrap_or_default()
    }

    fn recycle_string_buffer(&mut self, out: ScriptStringBuffer) {
        let (out, exceeded) = out.into_parts();
        if exceeded {
            self.string_limit_exceeded = true;
        }
        self.recycle_string(out);
    }

    fn recycle_string(&mut self, mut out: String) {
        out.clear();
        if self
            .max_string_bytes
            .is_none_or(|maximum| out.capacity() <= maximum)
        {
            self.strings_reuse.push(out);
        }
    }
}
