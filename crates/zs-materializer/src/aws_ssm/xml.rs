use zeroize::Zeroizing;

pub(crate) const MAX_DEPTH: usize = 16;
pub(crate) const MAX_BYTES: usize = 64 * 1024;

pub(crate) type Fields = Vec<Option<Zeroizing<String>>>;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

fn decode_entities(text: &str, out: &mut String) -> Result<(), Malformed> {
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let semi = after.find(';').ok_or(Malformed)?;
        let name = &after[..semi];
        let ch = match name {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = name.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(dec) = name.strip_prefix('#') {
                    dec.parse::<u32>().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32).ok_or(Malformed)?
            }
        };
        out.push(ch);
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Ok(())
}

fn tag_end(doc: &str, from: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (i, &b) in doc.as_bytes()[from..].iter().enumerate() {
        match (quote, b) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(b),
            (None, b'>') => return Some(from + i),
            (None, b'<') => return None,
            _ => {}
        }
    }
    None
}

struct Collector<'w> {
    wanted: &'w [&'w str],
    out: Fields,
    path: Vec<String>,
    collecting: Option<(usize, Zeroizing<String>)>,
    roots: usize,
}

impl<'w> Collector<'w> {
    fn new(wanted: &'w [&'w str]) -> Self {
        Self {
            wanted,
            out: (0..wanted.len()).map(|_| None).collect(),
            path: Vec::new(),
            collecting: None,
            roots: 0,
        }
    }

    fn start(&mut self, name: &str) -> Result<(), Malformed> {
        if self.collecting.is_some() {
            return Err(Malformed);
        }
        if self.path.is_empty() {
            self.roots += 1;
            if self.roots > 1 {
                return Err(Malformed);
            }
        }
        if self.path.len() >= MAX_DEPTH {
            return Err(Malformed);
        }
        self.path.push(name.to_string());
        let joined = self.path.join("/");
        if let Some(idx) = self.wanted.iter().position(|w| *w == joined) {
            if self.out[idx].is_some() {
                return Err(Malformed);
            }
            self.collecting = Some((idx, Zeroizing::new(String::new())));
        }
        Ok(())
    }

    fn text(&mut self, decoded: &str) {
        if let Some((_, buf)) = self.collecting.as_mut() {
            buf.push_str(decoded);
        }
    }

    fn end(&mut self, name: &str) -> Result<(), Malformed> {
        match self.path.pop() {
            Some(open) if open == name => {}
            _ => return Err(Malformed),
        }
        if let Some((idx, buf)) = self.collecting.take() {
            self.out[idx] = Some(buf);
        }
        Ok(())
    }

    fn finish(self) -> Result<Fields, Malformed> {
        if !self.path.is_empty() || self.roots != 1 {
            return Err(Malformed);
        }
        Ok(self.out)
    }
}

pub(crate) fn extract(doc: &str, wanted: &[&str]) -> Result<Fields, Malformed> {
    if doc.len() > MAX_BYTES {
        return Err(Malformed);
    }
    let mut c = Collector::new(wanted);
    let mut i = 0;
    if doc.starts_with("<?xml") {
        i = doc.find("?>").ok_or(Malformed)? + 2;
    }
    loop {
        let Some(rel) = doc[i..].find('<') else {
            if !doc[i..].trim().is_empty() {
                return Err(Malformed);
            }
            break;
        };
        let lt = i + rel;
        let text = &doc[i..lt];
        if c.path.is_empty() {
            if !text.trim().is_empty() {
                return Err(Malformed);
            }
        } else if c.collecting.is_some() {
            let mut decoded = Zeroizing::new(String::new());
            decode_entities(text, &mut decoded)?;
            c.text(&decoded);
        } else {
            decode_entities(text, &mut String::new())?;
        }
        let rest = &doc[lt..];
        if rest.starts_with("<!") || rest.starts_with("<?") {
            return Err(Malformed);
        }
        let gt = tag_end(doc, lt + 1).ok_or(Malformed)?;
        let inner = &doc[lt + 1..gt];
        if let Some(name) = inner.strip_prefix('/') {
            c.end(name.trim_end())?;
        } else {
            let self_closing = inner.ends_with('/');
            let inner = inner.trim_end_matches('/');
            let name = inner
                .split(|ch: char| ch.is_ascii_whitespace())
                .next()
                .unwrap_or_default();
            if name.is_empty() {
                return Err(Malformed);
            }
            c.start(name)?;
            if self_closing {
                c.end(name)?;
            }
        }
        i = gt + 1;
    }
    c.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn extracts_wanted_elements_and_refuses_hostile_shapes() {
        let ok = extract("<a><b>x &amp; y</b><c/></a>", &["a/b", "a/c", "a/d"]).unwrap();
        assert_eq!(ok[0].as_deref().map(String::as_str), Some("x & y"));
        assert_eq!(ok[1].as_deref().map(String::as_str), Some(""));
        assert!(ok[2].is_none());
        for hostile in [
            "<!DOCTYPE a><a/>",
            "<a><!-- c --></a>",
            "<a><b>1</b><b>2</b></a>",
            "<a><b><c/></b></a>",
            "<a></b>",
            "<a/><a/>",
            "<a>&xxe;</a>",
            "<a>",
        ] {
            assert_eq!(extract(hostile, &["a/b"]), Err(Malformed), "{hostile}");
        }
    }
}
