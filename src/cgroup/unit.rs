//! Properties a configuration puts on the container's unit.
//!
//! An engine that wants systemd to know something about the container, such
//! as the signal to stop it with, says so with an annotation naming the unit
//! property. The value carries its own type, since systemd types properties
//! strictly and refuses a call that gets one wrong.

use crate::{
    cgroup::dbus::systemd::Property,
    sys::error::{Error, Result},
};

/// What an annotation naming a unit property starts with.
const PREFIX: &str = "org.systemd.property.";

/// Microseconds in a second, which a `Sec` property is stated in.
const MICROSECONDS: u64 = 1_000_000;

/// One property, owning what it needs to be written later.
pub struct UnitProperty {
    name: String,
    value: Value,
}

/// A property's value, typed as systemd expects it.
enum Value {
    Bool(bool),
    Str(String),
    U64(u64),
    U32(u32),
    I64(i64),
    I32(i32),
}

impl UnitProperty {
    /// The property as the unit call takes it.
    #[must_use]
    pub fn as_property(&self) -> Property<'_> {
        match &self.value {
            Value::Bool(value) => Property::Bool(&self.name, *value),
            Value::Str(value) => Property::Str(&self.name, value),
            Value::U64(value) => Property::U64(&self.name, *value),
            Value::U32(value) => Property::U32(&self.name, *value),
            Value::I64(value) => Property::I64(&self.name, *value),
            Value::I32(value) => Property::I32(&self.name, *value),
        }
    }
}

/// Reads the properties an annotation set names.
///
/// Anything else in the set belongs to whoever wrote it and is left alone.
///
/// # Errors
///
/// When an annotation names a property whose value says a type this runtime
/// does not write, or says a type and then something that is not one. Both
/// mean the container would run under different limits from the ones asked
/// for, which is not something to discover from the outside later.
pub fn from_annotations(
    annotations: &[(&str, &str)],
) -> Result<Vec<UnitProperty>> {
    let mut out = Vec::new();
    for (key, value) in annotations {
        let Some(name) = key.strip_prefix(PREFIX) else {
            continue;
        };
        if name.is_empty() {
            return Err(Error::msg("cgroup: an annotation names no property"));
        }
        out.push(parse(name, value.trim_start())?);
    }
    Ok(out)
}

/// Reads one property, converting a `Sec` name to the `USec` systemd takes.
fn parse(name: &str, value: &str) -> Result<UnitProperty> {
    let (name, factor) = match name.strip_suffix("Sec") {
        Some(stem) if !stem.ends_with('U') => {
            (format!("{stem}USec"), MICROSECONDS)
        }
        _ => (name.to_owned(), 1),
    };
    Ok(UnitProperty {
        name,
        value: value_of(value, factor)?,
    })
}

/// Reads a value, which names its own type unless it is a bare number.
fn value_of(value: &str, factor: u64) -> Result<Value> {
    /// Multiplies, refusing a product that would not fit.
    fn scale(value: u64, factor: u64) -> Result<u64> {
        value
            .checked_mul(factor)
            .ok_or_else(|| Error::msg("cgroup: a property value is too large"))
    }
    /// Reads an unsigned number, whatever it will be narrowed to.
    fn unsigned(text: &str, factor: u64) -> Result<u64> {
        let value = text.parse::<u64>().map_err(|_| {
            Error::msg("cgroup: a property value is not a number")
        })?;
        scale(value, factor)
    }
    /// The same for a signed one.
    fn signed(text: &str, factor: u64) -> Result<i64> {
        let value = text.parse::<i64>().map_err(|_| {
            Error::msg("cgroup: a property value is not a number")
        })?;
        let factor = i64::try_from(factor)
            .map_err(|_| Error::msg("cgroup: a property value is too large"))?;
        value
            .checked_mul(factor)
            .ok_or_else(|| Error::msg("cgroup: a property value is too large"))
    }
    /// Narrows, refusing a value the type cannot hold.
    fn narrow<T: TryFrom<i64>>(value: i64) -> Result<T> {
        T::try_from(value)
            .map_err(|_| Error::msg("cgroup: a property value is out of range"))
    }

    match value {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if let Some(text) = value.strip_prefix('"') {
        let text = text.strip_suffix('"').ok_or_else(|| {
            Error::msg("cgroup: a property value is an unterminated string")
        })?;
        return Ok(Value::Str(text.to_owned()));
    }
    let Some((kind, text)) = value.split_once(' ') else {
        // A value that says no type is a signed 32-bit one, which is what
        // the properties an engine sets this way are typed as.
        return Ok(Value::I32(narrow(signed(value, factor)?)?));
    };
    let text = text.trim_start();
    match kind {
        "uint64" => Ok(Value::U64(unsigned(text, factor)?)),
        "int64" => Ok(Value::I64(signed(text, factor)?)),
        "uint32" => {
            let value = unsigned(text, factor)?;
            Ok(Value::U32(u32::try_from(value).map_err(|_| {
                Error::msg("cgroup: a property value is out of range")
            })?))
        }
        "int32" => Ok(Value::I32(narrow(signed(text, factor)?)?)),
        "string" => Ok(Value::Str(text.to_owned())),
        "boolean" => match text {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(Error::msg("cgroup: a property value is not a boolean")),
        },
        _ => Err(Error::msg("cgroup: a property names an unknown type")),
    }
}
