use thiserror::Error;

pub const DOUBLE: u8 = 0x01;
pub const STRING: u8 = 0x02;
pub const DOCUMENT: u8 = 0x03;
pub const ARRAY: u8 = 0x04;
pub const BINARY: u8 = 0x05;
pub const BOOLEAN: u8 = 0x08;
pub const INT32: u8 = 0x10;
pub const INT64: u8 = 0x12;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("malformed BSON document")]
pub struct Malformed;

#[derive(Clone, PartialEq)]
pub struct Element {
    pub kind: u8,
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Default, PartialEq)]
pub struct Doc {
    elements: Vec<Element>,
}

pub(crate) fn int32_at(bytes: &[u8], at: usize) -> Result<usize, Malformed> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or(Malformed)?
        .try_into()
        .map_err(|_| Malformed)?;
    usize::try_from(i32::from_le_bytes(raw)).map_err(|_| Malformed)
}

pub(crate) fn cstring_end(bytes: &[u8], at: usize) -> Result<usize, Malformed> {
    bytes
        .get(at..)
        .and_then(|rest| rest.iter().position(|b| *b == 0))
        .map(|i| at + i)
        .ok_or(Malformed)
}

fn string_len(bytes: &[u8], at: usize) -> Result<usize, Malformed> {
    let n = int32_at(bytes, at)?;
    if n == 0 || bytes.get(at + 3 + n) != Some(&0) {
        return Err(Malformed);
    }
    Ok(4 + n)
}

fn value_len(kind: u8, bytes: &[u8], at: usize) -> Result<usize, Malformed> {
    let len = match kind {
        0x06 | 0x0A | 0x7F | 0xFF => 0,
        0x08 => 1,
        0x10 => 4,
        0x01 | 0x09 | 0x11 | 0x12 => 8,
        0x07 => 12,
        0x13 => 16,
        0x02 | 0x0D | 0x0E => string_len(bytes, at)?,
        0x0C => string_len(bytes, at)? + 12,
        0x03 | 0x04 | 0x0F => {
            let n = int32_at(bytes, at)?;
            if n < 5 {
                return Err(Malformed);
            }
            n
        }
        0x05 => 5 + int32_at(bytes, at)?,
        0x0B => {
            let pattern = cstring_end(bytes, at)?;
            cstring_end(bytes, pattern + 1)? + 1 - at
        }
        _ => return Err(Malformed),
    };
    if at + len > bytes.len() {
        return Err(Malformed);
    }
    Ok(len)
}

pub const MAX_DOCUMENT_DEPTH: usize = 100;

fn document_frame(bytes: &[u8], at: usize, end: usize) -> Result<usize, Malformed> {
    let len = int32_at(bytes, at)?;
    let doc_end = at.checked_add(len).ok_or(Malformed)?;
    if len < 5 || doc_end > end || bytes.get(doc_end - 1) != Some(&0) {
        return Err(Malformed);
    }
    Ok(doc_end)
}

fn child_document(
    kind: u8,
    bytes: &[u8],
    value_at: usize,
    end: usize,
) -> Result<(usize, usize, usize), Malformed> {
    if kind != 0x0F {
        let doc_end = document_frame(bytes, value_at, end)?;
        return Ok((value_at, doc_end, doc_end));
    }
    let total = int32_at(bytes, value_at)?;
    let element_end = value_at.checked_add(total).ok_or(Malformed)?;
    if element_end > end {
        return Err(Malformed);
    }
    let scope_at = value_at + 4 + string_len(bytes, value_at + 4)?;
    let scope_end = document_frame(bytes, scope_at, element_end)?;
    if scope_end != element_end {
        return Err(Malformed);
    }
    Ok((scope_at, scope_end, element_end))
}

pub fn exceeds_depth(bytes: &[u8], at: usize, limit: usize) -> Result<bool, Malformed> {
    let total_end = document_frame(bytes, at, bytes.len())?;
    let mut stack: Vec<(usize, usize, usize)> = vec![(at + 4, total_end - 1, 1)];
    while let Some((mut cursor, mut end, mut depth)) = stack.pop() {
        loop {
            if cursor >= end {
                break;
            }
            let kind = *bytes.get(cursor).ok_or(Malformed)?;
            if kind == 0 {
                return Err(Malformed);
            }
            let name_end = cstring_end(bytes, cursor + 1)?;
            let value_at = name_end + 1;
            if matches!(kind, DOCUMENT | ARRAY | 0x0F) {
                let (doc_at, doc_end, element_end) = child_document(kind, bytes, value_at, end)?;
                if depth + 1 > limit {
                    return Ok(true);
                }
                stack.push((element_end, end, depth));
                cursor = doc_at + 4;
                end = doc_end - 1;
                depth += 1;
                continue;
            }
            let len = value_len(kind, bytes, value_at)?;
            if value_at.checked_add(len).is_none_or(|next| next > end) {
                return Err(Malformed);
            }
            cursor = value_at + len;
        }
    }
    Ok(false)
}

pub fn str_value(text: &str) -> Vec<u8> {
    let mut value = ((text.len() + 1) as i32).to_le_bytes().to_vec();
    value.extend_from_slice(text.as_bytes());
    value.push(0);
    value
}

fn decode_str(value: &[u8]) -> Option<&str> {
    let end = value.len().checked_sub(1)?;
    std::str::from_utf8(value.get(4..end)?).ok()
}

pub fn first_key(bytes: &[u8]) -> Option<&str> {
    let total = int32_at(bytes, 0).ok()?;
    if total < 6 || total > bytes.len() {
        return None;
    }
    let end = cstring_end(bytes, 5).ok()?;
    if end >= total {
        return None;
    }
    std::str::from_utf8(bytes.get(5..end)?).ok()
}

impl Doc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read(bytes: &[u8]) -> Result<(Self, usize), Malformed> {
        let total = int32_at(bytes, 0)?;
        if total < 5 || total > bytes.len() || bytes.get(total - 1) != Some(&0) {
            return Err(Malformed);
        }
        let body = bytes.get(..total - 1).ok_or(Malformed)?;
        let mut at = 4;
        let mut elements = Vec::new();
        while at < body.len() {
            let kind = body[at];
            let name_end = cstring_end(body, at + 1)?;
            let name = std::str::from_utf8(&body[at + 1..name_end])
                .map_err(|_| Malformed)?
                .to_string();
            let start = name_end + 1;
            let len = value_len(kind, body, start)?;
            elements.push(Element {
                kind,
                name,
                value: body[start..start + len].to_vec(),
            });
            at = start + len;
        }
        Ok((Self { elements }, total))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Malformed> {
        let (doc, used) = Self::read(bytes)?;
        if used == bytes.len() {
            Ok(doc)
        } else {
            Err(Malformed)
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; 4];
        for element in &self.elements {
            out.push(element.kind);
            out.extend_from_slice(element.name.as_bytes());
            out.push(0);
            out.extend_from_slice(&element.value);
        }
        out.push(0);
        let len = (out.len() as i32).to_le_bytes();
        out[..4].copy_from_slice(&len);
        out
    }

    pub fn elements(&self) -> &[Element] {
        &self.elements
    }

    pub fn first_key(&self) -> Option<&str> {
        self.elements.first().map(|e| e.name.as_str())
    }

    pub fn get(&self, name: &str) -> Option<&Element> {
        self.elements.iter().find(|e| e.name == name)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn remove(&mut self, name: &str) {
        self.elements.retain(|e| e.name != name);
    }

    pub fn set(&mut self, name: &str, kind: u8, value: Vec<u8>) {
        match self.elements.iter().position(|e| e.name == name) {
            Some(first) => {
                let mut position = 0;
                self.elements.retain(|e| {
                    let keep = position <= first || e.name != name;
                    position += 1;
                    keep
                });
                let element = &mut self.elements[first];
                element.kind = kind;
                element.value = value;
            }
            None => self.elements.push(Element {
                kind,
                name: name.to_string(),
                value,
            }),
        }
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        let element = self.get(name).filter(|e| e.kind == STRING)?;
        decode_str(&element.value)
    }

    pub fn bool(&self, name: &str) -> Option<bool> {
        let element = self.get(name).filter(|e| e.kind == BOOLEAN)?;
        element.value.first().map(|b| *b != 0)
    }

    pub fn int(&self, name: &str) -> Option<i64> {
        let element = self.get(name)?;
        match element.kind {
            INT32 => Some(i64::from(i32::from_le_bytes(
                element.value.as_slice().try_into().ok()?,
            ))),
            INT64 => Some(i64::from_le_bytes(
                element.value.as_slice().try_into().ok()?,
            )),
            DOUBLE => {
                let value = f64::from_le_bytes(element.value.as_slice().try_into().ok()?);
                (value.fract() == 0.0 && value.abs() < 9.0e15).then_some(value as i64)
            }
            _ => None,
        }
    }

    pub fn truthy(&self, name: &str) -> bool {
        self.int(name)
            .map(|n| n != 0)
            .or_else(|| self.bool(name))
            .unwrap_or(false)
    }

    pub fn binary(&self, name: &str) -> Option<&[u8]> {
        let element = self.get(name).filter(|e| e.kind == BINARY)?;
        element.value.get(5..)
    }

    pub fn doc(&self, name: &str) -> Option<Doc> {
        let element = self
            .get(name)
            .filter(|e| e.kind == DOCUMENT || e.kind == ARRAY)?;
        Doc::parse(&element.value).ok()
    }

    pub fn strings(&self, name: &str) -> Option<Vec<String>> {
        let element = self.get(name).filter(|e| e.kind == ARRAY)?;
        let array = Doc::parse(&element.value).ok()?;
        array
            .elements
            .iter()
            .map(|e| {
                if e.kind == STRING {
                    decode_str(&e.value).map(str::to_string)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn with_i32(mut self, name: &str, value: i32) -> Self {
        self.set(name, INT32, value.to_le_bytes().to_vec());
        self
    }

    pub fn with_i64(mut self, name: &str, value: i64) -> Self {
        self.set(name, INT64, value.to_le_bytes().to_vec());
        self
    }

    pub fn with_f64(mut self, name: &str, value: f64) -> Self {
        self.set(name, DOUBLE, value.to_le_bytes().to_vec());
        self
    }

    pub fn with_bool(mut self, name: &str, value: bool) -> Self {
        self.set(name, BOOLEAN, vec![u8::from(value)]);
        self
    }

    pub fn with_str(mut self, name: &str, value: &str) -> Self {
        self.set(name, STRING, str_value(value));
        self
    }

    pub fn with_binary(mut self, name: &str, value: &[u8]) -> Self {
        let mut raw = (value.len() as i32).to_le_bytes().to_vec();
        raw.push(0);
        raw.extend_from_slice(value);
        self.set(name, BINARY, raw);
        self
    }

    pub fn with_doc(mut self, name: &str, value: &Doc) -> Self {
        self.set(name, DOCUMENT, value.encode());
        self
    }

    pub fn with_array(mut self, name: &str, value: &Doc) -> Self {
        self.set(name, ARRAY, value.encode());
        self
    }

    pub fn with_strings(self, name: &str, values: &[&str]) -> Self {
        let array = values
            .iter()
            .enumerate()
            .fold(Doc::new(), |doc, (i, v)| doc.with_str(&i.to_string(), v));
        self.with_array(name, &array)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn every_kind() -> Doc {
        let mut scope = Vec::new();
        let code = str_value("f");
        let inner = Doc::new().with_i32("x", 1).encode();
        scope.extend_from_slice(&((4 + code.len() + inner.len()) as i32).to_le_bytes());
        scope.extend_from_slice(&code);
        scope.extend_from_slice(&inner);
        let mut pointer = str_value("c");
        pointer.extend_from_slice(&[7u8; 12]);
        let mut doc = Doc::new();
        for (kind, name, value) in [
            (0x01, "double", 2.5f64.to_le_bytes().to_vec()),
            (0x02, "string", str_value("text")),
            (0x03, "document", Doc::new().with_i32("a", 1).encode()),
            (0x04, "array", Doc::new().with_str("0", "a").encode()),
            (0x05, "binary", vec![3, 0, 0, 0, 0, 1, 2, 3]),
            (0x06, "undefined", Vec::new()),
            (0x07, "object_id", vec![9u8; 12]),
            (0x08, "boolean", vec![1]),
            (0x09, "datetime", 5i64.to_le_bytes().to_vec()),
            (0x0A, "null", Vec::new()),
            (0x0B, "regex", b"ab\0i\0".to_vec()),
            (0x0C, "pointer", pointer),
            (0x0D, "code", str_value("f()")),
            (0x0E, "symbol", str_value("s")),
            (0x0F, "scoped", scope),
            (0x10, "int32", 7i32.to_le_bytes().to_vec()),
            (0x11, "timestamp", 8u64.to_le_bytes().to_vec()),
            (0x12, "int64", 9i64.to_le_bytes().to_vec()),
            (0x13, "decimal", vec![1u8; 16]),
            (0xFF, "min", Vec::new()),
            (0x7F, "max", Vec::new()),
        ] {
            doc.set(name, kind, value);
        }
        doc
    }

    fn nested(depth: usize) -> Vec<u8> {
        let mut document = Doc::new().with_i32("probe", 1);
        for _ in 1..depth {
            document = Doc::new().with_doc("n", &document);
        }
        document.encode()
    }

    fn nested_array(depth: usize) -> Vec<u8> {
        let mut value = Doc::new().with_i32("probe", 1).encode();
        for _ in 1..depth {
            let mut document = Doc::new();
            document.set("a", ARRAY, value);
            value = document.encode();
        }
        value
    }

    #[test]
    fn a_document_at_the_depth_limit_is_accepted() {
        assert!(!exceeds_depth(&nested(MAX_DOCUMENT_DEPTH), 0, MAX_DOCUMENT_DEPTH).unwrap());
        assert!(!exceeds_depth(&nested_array(MAX_DOCUMENT_DEPTH), 0, MAX_DOCUMENT_DEPTH).unwrap());
    }

    #[test]
    fn a_document_past_the_depth_limit_is_refused() {
        assert!(exceeds_depth(&nested(MAX_DOCUMENT_DEPTH + 1), 0, MAX_DOCUMENT_DEPTH).unwrap());
        assert!(
            exceeds_depth(&nested_array(MAX_DOCUMENT_DEPTH + 1), 0, MAX_DOCUMENT_DEPTH).unwrap()
        );
    }

    #[test]
    fn a_child_that_overruns_its_parent_is_malformed() {
        let mut document = Doc::new();
        document.set("n", DOCUMENT, vec![100, 0, 0, 0]);
        assert_eq!(
            exceeds_depth(&document.encode(), 0, MAX_DOCUMENT_DEPTH),
            Err(Malformed)
        );
    }

    fn code_with_scope(code: &str, scope: &[u8]) -> Vec<u8> {
        let mut body = str_value(code);
        body.extend_from_slice(scope);
        let mut value = ((body.len() + 4) as i32).to_le_bytes().to_vec();
        value.extend_from_slice(&body);
        value
    }

    #[test]
    fn a_shallow_code_with_scope_is_accepted() {
        let scope = Doc::new().with_i32("x", 1).encode();
        let mut document = Doc::new();
        document.set("c", 0x0F, code_with_scope("function(){return x;}", &scope));
        assert!(!exceeds_depth(&document.encode(), 0, MAX_DOCUMENT_DEPTH).unwrap());
    }

    #[test]
    fn a_code_with_scope_whose_scope_is_too_deep_is_refused() {
        let mut document = Doc::new();
        document.set(
            "c",
            0x0F,
            code_with_scope("function(){return x;}", &nested(MAX_DOCUMENT_DEPTH)),
        );
        assert!(exceeds_depth(&document.encode(), 0, MAX_DOCUMENT_DEPTH).unwrap());
    }

    #[test]
    fn a_code_with_scope_whose_parts_disagree_is_malformed() {
        let scope = Doc::new().with_i32("x", 1).encode();
        let mut value = code_with_scope("f", &scope);
        value[0] = value[0].wrapping_sub(1);
        value.pop();
        let mut document = Doc::new();
        document.set("c", 0x0F, value);
        assert_eq!(
            exceeds_depth(&document.encode(), 0, MAX_DOCUMENT_DEPTH),
            Err(Malformed)
        );
    }

    #[test]
    fn an_early_terminator_hiding_a_deep_document_is_malformed() {
        let hidden = nested(MAX_DOCUMENT_DEPTH + 50);
        let mut child = vec![0u8];
        child.push(DOCUMENT);
        child.extend_from_slice(b"h\0");
        child.extend_from_slice(&hidden);
        child.push(0);
        let mut value = ((child.len() + 4) as i32).to_le_bytes().to_vec();
        value.extend_from_slice(&child);
        let mut document = Doc::new().with_str("insert", "c");
        document.set("a", DOCUMENT, value);
        assert_eq!(
            exceeds_depth(&document.encode(), 0, MAX_DOCUMENT_DEPTH),
            Err(Malformed)
        );
    }

    #[test]
    fn a_document_without_its_terminator_is_malformed() {
        let mut bytes = nested(2);
        bytes.pop();
        assert_eq!(exceeds_depth(&bytes, 0, MAX_DOCUMENT_DEPTH), Err(Malformed));
    }

    #[test]
    fn every_bson_kind_parses_and_encodes_byte_for_byte() {
        let bytes = every_kind().encode();
        let parsed = Doc::parse(&bytes).unwrap();
        assert_eq!(parsed.encode(), bytes);
        assert_eq!(parsed.first_key(), Some("double"));
        assert_eq!(parsed.str("string"), Some("text"));
        assert_eq!(parsed.int("int32"), Some(7));
        assert_eq!(parsed.int("int64"), Some(9));
        assert_eq!(parsed.bool("boolean"), Some(true));
        assert_eq!(parsed.binary("binary"), Some(&[1u8, 2, 3][..]));
        assert_eq!(parsed.doc("document").unwrap().int("a"), Some(1));
        assert!(parsed.contains("max"));
    }

    #[test]
    fn read_returns_the_document_length_and_leaves_trailing_bytes() {
        let mut bytes = Doc::new().with_str("hello", "x").encode();
        let len = bytes.len();
        bytes.extend_from_slice(b"tail");
        let (doc, used) = Doc::read(&bytes).unwrap();
        assert_eq!(used, len);
        assert_eq!(doc.str("hello"), Some("x"));
        assert!(
            Doc::parse(&bytes).is_err(),
            "parse needs exactly one document"
        );
    }

    #[test]
    fn malformed_documents_are_refused() {
        let good = Doc::new().with_str("a", "b").encode();
        let mut too_long = good.clone();
        too_long[0] = 200;
        let mut no_terminator = good.clone();
        let last = no_terminator.len() - 1;
        no_terminator[last] = 1;
        let mut unknown_kind = good.clone();
        unknown_kind[4] = 0x14;
        let mut string_without_nul = good.clone();
        let nul = string_without_nul.len() - 2;
        string_without_nul[nul] = b'x';
        let mut bad_name = good.clone();
        bad_name[5] = 0xff;
        for (case, bytes) in [
            ("length past the end", too_long),
            ("no terminator", no_terminator),
            ("unknown kind", unknown_kind),
            ("string without NUL", string_without_nul),
            ("name not UTF-8", bad_name),
            ("length below 5", vec![4, 0, 0, 0]),
            ("empty", Vec::new()),
        ] {
            assert!(Doc::parse(&bytes).is_err(), "{case}");
        }
        let mut overrun = Doc::new().with_i32("a", 1).encode();
        overrun[0] -= 2;
        assert!(
            Doc::parse(&overrun).is_err(),
            "an element running past the end"
        );
    }

    #[test]
    fn numbers_and_truth_follow_the_server_types() {
        let doc = Doc::new()
            .with_f64("ok", 1.0)
            .with_f64("half", 0.5)
            .with_i32("zero", 0)
            .with_bool("yes", true)
            .with_i64("big", 1 << 40);
        assert!(doc.truthy("ok"));
        assert!(!doc.truthy("zero"));
        assert!(doc.truthy("yes"));
        assert!(!doc.truthy("absent"));
        assert_eq!(doc.int("ok"), Some(1));
        assert_eq!(doc.int("half"), None);
        assert_eq!(doc.int("big"), Some(1 << 40));
    }

    #[test]
    fn set_replaces_in_place_and_remove_drops_every_copy() {
        let mut doc = Doc::new()
            .with_str("a", "1")
            .with_str("b", "2")
            .with_str("c", "3");
        doc.set("b", STRING, str_value("two"));
        doc.remove("c");
        doc.set("d", INT32, 4i32.to_le_bytes().to_vec());
        let names: Vec<&str> = doc.elements().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "d"]);
        assert_eq!(doc.str("b"), Some("two"));
    }

    #[test]
    fn set_keeps_the_first_copy_of_a_duplicate_key_and_drops_the_rest() {
        let mut bytes = Doc::new()
            .with_str("a", "1")
            .with_str("k", "old")
            .with_str("b", "2")
            .encode();
        let tail = Doc::new().with_str("k", "dup").with_str("c", "3").encode();
        bytes.pop();
        bytes.extend_from_slice(&tail[4..]);
        let total = (bytes.len() as i32).to_le_bytes();
        bytes[..4].copy_from_slice(&total);
        let mut doc = Doc::parse(&bytes).unwrap();
        assert_eq!(doc.elements().iter().filter(|e| e.name == "k").count(), 2);
        doc.set("k", STRING, str_value("new"));
        let names: Vec<&str> = doc.elements().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a", "k", "b", "c"]);
        assert_eq!(doc.str("k"), Some("new"));
    }

    #[test]
    fn string_arrays_read_only_when_every_item_is_a_string() {
        let doc = Doc::new()
            .with_strings("hosts", &["a:1", "b:2"])
            .with_array("mixed", &Doc::new().with_str("0", "a").with_i32("1", 2));
        assert_eq!(
            doc.strings("hosts"),
            Some(vec!["a:1".to_string(), "b:2".to_string()])
        );
        assert_eq!(doc.strings("mixed"), None);
        assert_eq!(doc.get("hosts").unwrap().kind, ARRAY);
    }

    #[test]
    fn first_key_reads_without_a_full_parse() {
        let bytes = Doc::new().with_i32("find", 1).with_str("$db", "x").encode();
        assert_eq!(first_key(&bytes), Some("find"));
        assert_eq!(first_key(&Doc::new().encode()), None);
        assert_eq!(first_key(&[1, 2]), None);
    }
}
