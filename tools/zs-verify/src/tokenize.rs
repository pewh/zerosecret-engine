pub(crate) fn tokenize(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut started = false;
    for c in input.chars() {
        match c {
            '\'' => {
                in_single = !in_single;
                started = true;
            }
            ' ' | '\t' if !in_single => {
                if started || !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                    started = false;
                }
            }
            other => {
                current.push(other);
                started = true;
            }
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}
