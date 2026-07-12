#![forbid(unsafe_code)]

//! A bounded executable JSON-schema subset for Splash capability contracts.
//!
//! Supported keywords: `type`, `properties`, `required`,
//! `additionalProperties`, `items`, `minItems`, `maxItems`, `minLength`,
//! `maxLength`, `minimum`, `maximum`, and `enum`. Annotation keywords such as
//! `title` and `description` are accepted but do not affect validation.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use serde_json::{Map, Value};

pub const MAX_SCHEMA_DEPTH: usize = 32;
pub const MAX_SCHEMA_PROPERTIES: usize = 128;
pub const MAX_SCHEMA_ENUM_VALUES: usize = 128;
pub const MAX_SCHEMA_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct JsonSchema {
    source: Value,
    node: SchemaNode,
}

impl JsonSchema {
    pub fn compile(source: Value) -> Result<Self, SchemaError> {
        if source.to_string().len() > MAX_SCHEMA_BYTES {
            return Err(SchemaError::TooLarge {
                maximum: MAX_SCHEMA_BYTES,
            });
        }
        let node = SchemaNode::compile(&source, "$", 0)?;
        Ok(Self { source, node })
    }

    pub fn source(&self) -> &Value {
        &self.source
    }

    pub fn validate(&self, value: &Value) -> Result<(), SchemaViolation> {
        self.node.validate(value, "$")
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SchemaNode {
    kind: SchemaKind,
    enum_values: Option<Vec<Value>>,
}

#[derive(Clone, Debug, PartialEq)]
enum SchemaKind {
    Any,
    Null,
    Boolean,
    Number(NumericConstraints),
    Integer(NumericConstraints),
    String(StringConstraints),
    Array(ArrayConstraints),
    Object(ObjectConstraints),
}

#[derive(Clone, Debug, Default, PartialEq)]
struct NumericConstraints {
    minimum: Option<ExactNumber>,
    maximum: Option<ExactNumber>,
}

/// A finite JSON number normalized for exact comparisons without a floating
/// point conversion. The represented value is digits times 10 to the scale.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactNumber {
    negative: bool,
    digits: Vec<u8>,
    scale: i64,
}

impl ExactNumber {
    fn from_value(value: &Value) -> Option<Self> {
        Self::parse(&value.as_number()?.to_string())
    }

    fn parse(source: &str) -> Option<Self> {
        let bytes = source.as_bytes();
        let mut cursor = 0;
        let negative = match bytes.first() {
            Some(b'-') => {
                cursor = 1;
                true
            }
            _ => false,
        };

        let mut digits = Vec::with_capacity(bytes.len());
        let integer_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            digits.push(bytes[cursor]);
            cursor += 1;
        }
        if cursor == integer_start {
            return None;
        }

        let mut fractional_digits = 0usize;
        if bytes.get(cursor) == Some(&b'.') {
            cursor += 1;
            let fractional_start = cursor;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                digits.push(bytes[cursor]);
                cursor += 1;
            }
            fractional_digits = cursor - fractional_start;
            if fractional_digits == 0 {
                return None;
            }
        }

        let mut exponent = 0i64;
        if matches!(bytes.get(cursor), Some(b'e' | b'E')) {
            cursor += 1;
            let exponent_negative = match bytes.get(cursor) {
                Some(b'-') => {
                    cursor += 1;
                    true
                }
                Some(b'+') => {
                    cursor += 1;
                    false
                }
                _ => false,
            };
            let exponent_start = cursor;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                exponent = exponent
                    .checked_mul(10)?
                    .checked_add(i64::from(bytes[cursor] - b'0'))?;
                cursor += 1;
            }
            if cursor == exponent_start {
                return None;
            }
            if exponent_negative {
                exponent = exponent.checked_neg()?;
            }
        }
        if cursor != bytes.len() {
            return None;
        }

        let first_nonzero = digits.iter().position(|digit| *digit != b'0');
        let Some(first_nonzero) = first_nonzero else {
            return Some(Self {
                negative: false,
                digits: vec![b'0'],
                scale: 0,
            });
        };
        let mut digits = digits.split_off(first_nonzero);
        let fractional_digits = i64::try_from(fractional_digits).ok()?;
        let mut scale = exponent.checked_sub(fractional_digits)?;
        while digits.last() == Some(&b'0') {
            digits.pop();
            scale = scale.checked_add(1)?;
        }
        let digit_count = i64::try_from(digits.len()).ok()?;
        scale.checked_add(digit_count)?;

        Some(Self {
            negative,
            digits,
            scale,
        })
    }

    fn is_integer(&self) -> bool {
        self.scale >= 0
    }

    fn compare(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self.compare_magnitude(other),
            (true, true) => other.compare_magnitude(self),
        }
    }

    fn compare_magnitude(&self, other: &Self) -> Ordering {
        let self_order = self
            .scale
            .saturating_add(i64::try_from(self.digits.len()).unwrap_or(i64::MAX));
        let other_order = other
            .scale
            .saturating_add(i64::try_from(other.digits.len()).unwrap_or(i64::MAX));
        match self_order.cmp(&other_order) {
            Ordering::Equal => {}
            ordering => return ordering,
        }

        let length = self.digits.len().max(other.digits.len());
        for index in 0..length {
            match self
                .digits
                .get(index)
                .copied()
                .unwrap_or(b'0')
                .cmp(&other.digits.get(index).copied().unwrap_or(b'0'))
            {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
struct StringConstraints {
    min_length: Option<usize>,
    max_length: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct ArrayConstraints {
    items: Option<Box<SchemaNode>>,
    min_items: Option<usize>,
    max_items: Option<usize>,
}

#[derive(Clone, Debug, PartialEq)]
struct ObjectConstraints {
    properties: BTreeMap<String, SchemaNode>,
    required: BTreeSet<String>,
    additional_properties: bool,
}

impl SchemaNode {
    fn compile(source: &Value, path: &str, depth: usize) -> Result<Self, SchemaError> {
        if depth > MAX_SCHEMA_DEPTH {
            return Err(SchemaError::TooDeep {
                maximum: MAX_SCHEMA_DEPTH,
            });
        }
        let object = source
            .as_object()
            .ok_or_else(|| SchemaError::ExpectedObject {
                path: path.to_owned(),
            })?;
        validate_keywords(object, path)?;

        let has_object_keywords = object.contains_key("properties")
            || object.contains_key("required")
            || object.contains_key("additionalProperties");
        let has_array_keywords = object.contains_key("items")
            || object.contains_key("minItems")
            || object.contains_key("maxItems");
        let kind = match object.get("type") {
            Some(Value::String(kind)) => parse_kind(kind, object, path, depth)?,
            Some(_) => {
                return Err(SchemaError::InvalidKeyword {
                    path: path.to_owned(),
                    keyword: "type".to_owned(),
                    message: "must be a string".to_owned(),
                })
            }
            None if has_object_keywords && has_array_keywords => {
                return Err(SchemaError::InvalidKeyword {
                    path: path.to_owned(),
                    keyword: "type".to_owned(),
                    message: "is required when object and array keywords are mixed".to_owned(),
                })
            }
            None if has_object_keywords => {
                validate_type_keywords(object, path, "object")?;
                SchemaKind::Object(parse_object(object, path, depth)?)
            }
            None if has_array_keywords => {
                validate_type_keywords(object, path, "array")?;
                SchemaKind::Array(parse_array(object, path, depth)?)
            }
            None => {
                validate_type_keywords(object, path, "any")?;
                SchemaKind::Any
            }
        };
        let enum_values = parse_enum(object, path)?;

        Ok(Self { kind, enum_values })
    }

    fn validate(&self, value: &Value, path: &str) -> Result<(), SchemaViolation> {
        match &self.kind {
            SchemaKind::Any => {}
            SchemaKind::Null => expect_type(value.is_null(), path, "null")?,
            SchemaKind::Boolean => expect_type(value.is_boolean(), path, "boolean")?,
            SchemaKind::Number(constraints) => {
                let number = ExactNumber::from_value(value)
                    .ok_or_else(|| SchemaViolation::new(path, "expected number"))?;
                validate_numeric(&number, constraints, path)?;
            }
            SchemaKind::Integer(constraints) => {
                let number = ExactNumber::from_value(value)
                    .ok_or_else(|| SchemaViolation::new(path, "expected integer"))?;
                if !number.is_integer() {
                    return Err(SchemaViolation::new(path, "expected integer"));
                }
                validate_numeric(&number, constraints, path)?;
            }
            SchemaKind::String(constraints) => {
                let string = value
                    .as_str()
                    .ok_or_else(|| SchemaViolation::new(path, "expected string"))?;
                let length = string.chars().count();
                if constraints
                    .min_length
                    .is_some_and(|minimum| length < minimum)
                {
                    return Err(SchemaViolation::new(
                        path,
                        "string is shorter than minLength",
                    ));
                }
                if constraints
                    .max_length
                    .is_some_and(|maximum| length > maximum)
                {
                    return Err(SchemaViolation::new(
                        path,
                        "string is longer than maxLength",
                    ));
                }
            }
            SchemaKind::Array(constraints) => {
                let values = value
                    .as_array()
                    .ok_or_else(|| SchemaViolation::new(path, "expected array"))?;
                if constraints
                    .min_items
                    .is_some_and(|minimum| values.len() < minimum)
                {
                    return Err(SchemaViolation::new(
                        path,
                        "array has fewer than minItems values",
                    ));
                }
                if constraints
                    .max_items
                    .is_some_and(|maximum| values.len() > maximum)
                {
                    return Err(SchemaViolation::new(
                        path,
                        "array has more than maxItems values",
                    ));
                }
                if let Some(items) = &constraints.items {
                    for (index, item) in values.iter().enumerate() {
                        items.validate(item, &format!("{path}[{index}]"))?;
                    }
                }
            }
            SchemaKind::Object(constraints) => {
                let values = value
                    .as_object()
                    .ok_or_else(|| SchemaViolation::new(path, "expected object"))?;
                for key in &constraints.required {
                    if !values.contains_key(key) {
                        return Err(SchemaViolation::new(
                            path,
                            format!("missing required property {key:?}"),
                        ));
                    }
                }
                for (key, value) in values {
                    match constraints.properties.get(key) {
                        Some(schema) => schema.validate(value, &property_path(path, key))?,
                        None if !constraints.additional_properties => {
                            return Err(SchemaViolation::new(
                                path,
                                format!("additional property {key:?} is not allowed"),
                            ));
                        }
                        None => {}
                    }
                }
            }
        }

        if let Some(enum_values) = &self.enum_values {
            if !enum_values.iter().any(|allowed| allowed == value) {
                return Err(SchemaViolation::new(path, "value is not in enum"));
            }
        }
        Ok(())
    }
}

fn parse_kind(
    kind: &str,
    object: &Map<String, Value>,
    path: &str,
    depth: usize,
) -> Result<SchemaKind, SchemaError> {
    validate_type_keywords(object, path, kind)?;
    match kind {
        "null" => Ok(SchemaKind::Null),
        "boolean" => Ok(SchemaKind::Boolean),
        "number" => Ok(SchemaKind::Number(parse_numeric(object, path)?)),
        "integer" => Ok(SchemaKind::Integer(parse_numeric(object, path)?)),
        "string" => Ok(SchemaKind::String(parse_string(object, path)?)),
        "array" => Ok(SchemaKind::Array(parse_array(object, path, depth)?)),
        "object" => Ok(SchemaKind::Object(parse_object(object, path, depth)?)),
        _ => Err(SchemaError::InvalidKeyword {
            path: path.to_owned(),
            keyword: "type".to_owned(),
            message: format!("unsupported type {kind:?}"),
        }),
    }
}

fn parse_numeric(
    object: &Map<String, Value>,
    path: &str,
) -> Result<NumericConstraints, SchemaError> {
    let minimum = parse_number(object, "minimum", path)?;
    let maximum = parse_number(object, "maximum", path)?;
    if minimum
        .as_ref()
        .zip(maximum.as_ref())
        .is_some_and(|(minimum, maximum)| minimum.compare(maximum) == Ordering::Greater)
    {
        return Err(SchemaError::InvalidKeyword {
            path: path.to_owned(),
            keyword: "minimum".to_owned(),
            message: "cannot exceed maximum".to_owned(),
        });
    }
    Ok(NumericConstraints { minimum, maximum })
}

fn parse_string(object: &Map<String, Value>, path: &str) -> Result<StringConstraints, SchemaError> {
    let min_length = parse_usize(object, "minLength", path)?;
    let max_length = parse_usize(object, "maxLength", path)?;
    if min_length
        .zip(max_length)
        .is_some_and(|(minimum, maximum)| minimum > maximum)
    {
        return Err(SchemaError::InvalidKeyword {
            path: path.to_owned(),
            keyword: "minLength".to_owned(),
            message: "cannot exceed maxLength".to_owned(),
        });
    }
    Ok(StringConstraints {
        min_length,
        max_length,
    })
}

fn parse_array(
    object: &Map<String, Value>,
    path: &str,
    depth: usize,
) -> Result<ArrayConstraints, SchemaError> {
    let min_items = parse_usize(object, "minItems", path)?;
    let max_items = parse_usize(object, "maxItems", path)?;
    if min_items
        .zip(max_items)
        .is_some_and(|(minimum, maximum)| minimum > maximum)
    {
        return Err(SchemaError::InvalidKeyword {
            path: path.to_owned(),
            keyword: "minItems".to_owned(),
            message: "cannot exceed maxItems".to_owned(),
        });
    }
    let items = object
        .get("items")
        .map(|schema| {
            SchemaNode::compile(schema, &format!("{path}.items"), depth + 1).map(Box::new)
        })
        .transpose()?;
    Ok(ArrayConstraints {
        items,
        min_items,
        max_items,
    })
}

fn parse_object(
    object: &Map<String, Value>,
    path: &str,
    depth: usize,
) -> Result<ObjectConstraints, SchemaError> {
    let mut properties = BTreeMap::new();
    if let Some(property_schemas) = object.get("properties") {
        let property_schemas = property_schemas
            .as_object()
            .ok_or_else(|| invalid_keyword(path, "properties", "must be an object"))?;
        if property_schemas.len() > MAX_SCHEMA_PROPERTIES {
            return Err(SchemaError::TooManyProperties {
                maximum: MAX_SCHEMA_PROPERTIES,
            });
        }
        for (key, schema) in property_schemas {
            properties.insert(
                key.clone(),
                SchemaNode::compile(schema, &property_path(path, key), depth + 1)?,
            );
        }
    }

    let mut required = BTreeSet::new();
    if let Some(required_values) = object.get("required") {
        let required_values = required_values
            .as_array()
            .ok_or_else(|| invalid_keyword(path, "required", "must be an array"))?;
        for value in required_values {
            let key = value
                .as_str()
                .ok_or_else(|| invalid_keyword(path, "required", "must contain strings"))?;
            if !required.insert(key.to_owned()) {
                return Err(invalid_keyword(
                    path,
                    "required",
                    "cannot contain duplicates",
                ));
            }
        }
    }

    let additional_properties = match object.get("additionalProperties") {
        Some(Value::Bool(value)) => *value,
        Some(_) => {
            return Err(invalid_keyword(
                path,
                "additionalProperties",
                "must be a boolean in the Splash subset",
            ))
        }
        None => true,
    };
    Ok(ObjectConstraints {
        properties,
        required,
        additional_properties,
    })
}

fn parse_enum(object: &Map<String, Value>, path: &str) -> Result<Option<Vec<Value>>, SchemaError> {
    let Some(values) = object.get("enum") else {
        return Ok(None);
    };
    let values = values
        .as_array()
        .ok_or_else(|| invalid_keyword(path, "enum", "must be an array"))?;
    if values.len() > MAX_SCHEMA_ENUM_VALUES {
        return Err(SchemaError::TooManyEnumValues {
            maximum: MAX_SCHEMA_ENUM_VALUES,
        });
    }
    Ok(Some(values.clone()))
}

fn parse_usize(
    object: &Map<String, Value>,
    keyword: &str,
    path: &str,
) -> Result<Option<usize>, SchemaError> {
    let Some(value) = object.get(keyword) else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .ok_or_else(|| invalid_keyword(path, keyword, "must be a non-negative integer"))?;
    usize::try_from(value)
        .map(Some)
        .map_err(|_| invalid_keyword(path, keyword, "is too large for this platform"))
}

fn parse_number(
    object: &Map<String, Value>,
    keyword: &str,
    path: &str,
) -> Result<Option<ExactNumber>, SchemaError> {
    let Some(value) = object.get(keyword) else {
        return Ok(None);
    };
    ExactNumber::from_value(value)
        .map(Some)
        .ok_or_else(|| invalid_keyword(path, keyword, "must be a supported JSON number"))
}

fn validate_keywords(object: &Map<String, Value>, path: &str) -> Result<(), SchemaError> {
    const SUPPORTED: &[&str] = &[
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "title",
        "description",
        "default",
        "examples",
        "$schema",
        "$id",
    ];
    for key in object.keys() {
        if !SUPPORTED.contains(&key.as_str()) {
            return Err(SchemaError::UnsupportedKeyword {
                path: path.to_owned(),
                keyword: key.clone(),
            });
        }
    }
    Ok(())
}

fn validate_type_keywords(
    object: &Map<String, Value>,
    path: &str,
    kind: &str,
) -> Result<(), SchemaError> {
    const ANNOTATIONS: &[&str] = &[
        "title",
        "description",
        "default",
        "examples",
        "$schema",
        "$id",
    ];
    const UNIVERSAL: &[&str] = &["type", "enum"];
    let type_keywords: &[&str] = match kind {
        "number" | "integer" => &["minimum", "maximum"],
        "string" => &["minLength", "maxLength"],
        "array" => &["items", "minItems", "maxItems"],
        "object" => &["properties", "required", "additionalProperties"],
        "null" | "boolean" | "any" => &[],
        _ => {
            return Err(SchemaError::InvalidKeyword {
                path: path.to_owned(),
                keyword: "type".to_owned(),
                message: format!("unsupported type {kind:?}"),
            })
        }
    };
    for key in object.keys() {
        if !ANNOTATIONS.contains(&key.as_str())
            && !UNIVERSAL.contains(&key.as_str())
            && !type_keywords.contains(&key.as_str())
        {
            return Err(SchemaError::InvalidKeyword {
                path: path.to_owned(),
                keyword: key.clone(),
                message: format!("does not apply to {kind}"),
            });
        }
    }
    Ok(())
}

fn validate_numeric(
    value: &ExactNumber,
    constraints: &NumericConstraints,
    path: &str,
) -> Result<(), SchemaViolation> {
    if constraints
        .minimum
        .as_ref()
        .is_some_and(|minimum| value.compare(minimum) == Ordering::Less)
    {
        return Err(SchemaViolation::new(path, "number is below minimum"));
    }
    if constraints
        .maximum
        .as_ref()
        .is_some_and(|maximum| value.compare(maximum) == Ordering::Greater)
    {
        return Err(SchemaViolation::new(path, "number is above maximum"));
    }
    Ok(())
}

fn expect_type(matches: bool, path: &str, expected: &str) -> Result<(), SchemaViolation> {
    if matches {
        Ok(())
    } else {
        Err(SchemaViolation::new(path, format!("expected {expected}")))
    }
}

fn property_path(path: &str, key: &str) -> String {
    format!("{path}[{key:?}]")
}

fn invalid_keyword(path: &str, keyword: &str, message: &str) -> SchemaError {
    SchemaError::InvalidKeyword {
        path: path.to_owned(),
        keyword: keyword.to_owned(),
        message: message.to_owned(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaViolation {
    pub path: String,
    pub message: String,
}

impl SchemaViolation {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl Display for SchemaViolation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for SchemaViolation {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaError {
    ExpectedObject {
        path: String,
    },
    InvalidKeyword {
        path: String,
        keyword: String,
        message: String,
    },
    UnsupportedKeyword {
        path: String,
        keyword: String,
    },
    TooDeep {
        maximum: usize,
    },
    TooManyProperties {
        maximum: usize,
    },
    TooManyEnumValues {
        maximum: usize,
    },
    TooLarge {
        maximum: usize,
    },
}

impl Display for SchemaError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedObject { path } => write!(formatter, "{path}: schema must be an object"),
            Self::InvalidKeyword {
                path,
                keyword,
                message,
            } => write!(formatter, "{path}: invalid {keyword}: {message}"),
            Self::UnsupportedKeyword { path, keyword } => {
                write!(formatter, "{path}: unsupported schema keyword {keyword}")
            }
            Self::TooDeep { maximum } => {
                write!(formatter, "schema exceeds depth limit of {maximum}")
            }
            Self::TooManyProperties { maximum } => {
                write!(formatter, "schema exceeds property limit of {maximum}")
            }
            Self::TooManyEnumValues { maximum } => {
                write!(formatter, "schema exceeds enum limit of {maximum}")
            }
            Self::TooLarge { maximum } => {
                write!(formatter, "schema exceeds byte limit of {maximum}")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn release_schema() -> JsonSchema {
        JsonSchema::compile(json!({
            "type": "object",
            "properties": {
                "title": {"type": "string", "minLength": 1, "maxLength": 80},
                "priority": {"type": "integer", "minimum": 1, "maximum": 5},
                "labels": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["bug", "feature"]},
                    "maxItems": 3
                }
            },
            "required": ["title", "priority"],
            "additionalProperties": false
        }))
        .unwrap()
    }

    #[test]
    fn validates_nested_object_array_and_scalar_constraints() {
        let schema = release_schema();
        schema
            .validate(&json!({
                "title": "Ship Splash",
                "priority": 1,
                "labels": ["feature"]
            }))
            .unwrap();

        let missing = schema
            .validate(&json!({"title": "Ship Splash"}))
            .unwrap_err();
        assert!(missing.message.contains("missing required"));
        let unexpected = schema
            .validate(&json!({"title": "Ship", "priority": 1, "extra": true}))
            .unwrap_err();
        assert!(unexpected.message.contains("additional property"));
        let enum_error = schema
            .validate(&json!({"title": "Ship", "priority": 1, "labels": ["docs"]}))
            .unwrap_err();
        assert_eq!(enum_error.path, "$[\"labels\"][0]");
    }

    #[test]
    fn supports_schema_annotations_but_rejects_unknown_keywords() {
        JsonSchema::compile(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Example",
            "description": "An example schema",
            "type": "object"
        }))
        .unwrap();

        assert!(matches!(
            JsonSchema::compile(json!({"type": "object", "oneOf": []})),
            Err(SchemaError::UnsupportedKeyword { keyword, .. }) if keyword == "oneOf"
        ));
    }

    #[test]
    fn rejects_invalid_schema_bounds() {
        assert!(matches!(
            JsonSchema::compile(json!({"type": "array", "minItems": 2, "maxItems": 1})),
            Err(SchemaError::InvalidKeyword { keyword, .. }) if keyword == "minItems"
        ));
        assert!(matches!(
            JsonSchema::compile(json!({"type": "string", "minLength": -1})),
            Err(SchemaError::InvalidKeyword { keyword, .. }) if keyword == "minLength"
        ));
    }

    #[test]
    fn rejects_keywords_that_do_not_apply_to_the_declared_type() {
        assert!(matches!(
            JsonSchema::compile(json!({"type": "string", "properties": {}})),
            Err(SchemaError::InvalidKeyword { keyword, .. }) if keyword == "properties"
        ));
    }

    #[test]
    fn compares_large_integer_constraints_without_floating_point_rounding() {
        let maximum = 9_007_199_254_740_992_u64;
        let schema = JsonSchema::compile(json!({
            "type": "integer",
            "maximum": maximum
        }))
        .unwrap();

        schema.validate(&Value::from(maximum)).unwrap();
        let error = schema.validate(&Value::from(maximum + 1)).unwrap_err();
        assert_eq!(error.message, "number is above maximum");

        let integer_schema = JsonSchema::compile(json!({"type": "integer"})).unwrap();
        integer_schema.validate(&json!(1.0)).unwrap();
    }

    #[test]
    fn compares_decimal_constraints_without_floating_point_rounding() {
        let schema = JsonSchema::compile(
            serde_json::from_str(
                r#"{"type":"number","maximum":0.1000000000000000000000000000000000000001}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let allowed = serde_json::from_str("0.1000000000000000000000000000000000000001").unwrap();
        let rejected = serde_json::from_str("0.1000000000000000000000000000000000000002").unwrap();

        schema.validate(&allowed).unwrap();
        let error = schema.validate(&rejected).unwrap_err();
        assert_eq!(error.message, "number is above maximum");
    }

    #[test]
    fn rejects_schemas_larger_than_the_source_budget() {
        let schema = json!({"description": "x".repeat(MAX_SCHEMA_BYTES)});
        assert!(matches!(
            JsonSchema::compile(schema),
            Err(SchemaError::TooLarge { maximum }) if maximum == MAX_SCHEMA_BYTES
        ));
    }
}
