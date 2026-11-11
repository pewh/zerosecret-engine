use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

pub const MAX_FRAME: usize = 32 * 1024 * 1024;
pub const MAX_ELEMENTS: u64 = 1_048_576;

const MAX_HEADER: usize = 32;
const PREALLOCATED_ARGS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    ClientTls,
    NonResp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rewrite {
    Unchanged,
    Rewritten,
    UserMismatch,
}

pub struct Command {
    args: Vec<Zeroizing<Vec<u8>>>,
}

impl Command {
    pub fn new(args: Vec<Vec<u8>>) -> Self {
        Self {
            args: args.into_iter().map(Zeroizing::new).collect(),
        }
    }

    pub fn from_zeroized(args: Vec<Zeroizing<Vec<u8>>>) -> Self {
        Self { args }
    }

    pub fn args(&self) -> &[Zeroizing<Vec<u8>>] {
        &self.args
    }

    pub fn is(&self, name: &str) -> bool {
        self.args
            .first()
            .is_some_and(|arg| arg.eq_ignore_ascii_case(name.as_bytes()))
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(format!("*{}\r\n", self.args.len()).as_bytes());
        for arg in &self.args {
            out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
            out.extend_from_slice(arg);
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    pub fn rewrite_auth(&mut self, user: &str, names_user: bool, credential: &[u8]) -> Rewrite {
        if self.is("AUTH") {
            return self.rewrite_auth_command(user, names_user, credential);
        }
        if self.is("HELLO") {
            return self.rewrite_hello_auth(user, credential);
        }
        Rewrite::Unchanged
    }

    fn rewrite_auth_command(&mut self, user: &str, names_user: bool, credential: &[u8]) -> Rewrite {
        match self.args.len() {
            1 => Rewrite::Unchanged,
            2 => {
                if user != "default" {
                    return Rewrite::UserMismatch;
                }
                let mut args = vec![Zeroizing::new(b"AUTH".to_vec())];
                if names_user {
                    args.push(Zeroizing::new(user.as_bytes().to_vec()));
                }
                args.push(Zeroizing::new(credential.to_vec()));
                self.args = args;
                Rewrite::Rewritten
            }
            3 => {
                if self.args[1].as_slice() != user.as_bytes() {
                    return Rewrite::UserMismatch;
                }
                self.args[1] = Zeroizing::new(user.as_bytes().to_vec());
                self.args[2] = Zeroizing::new(credential.to_vec());
                Rewrite::Rewritten
            }
            _ => Rewrite::UserMismatch,
        }
    }

    fn rewrite_hello_auth(&mut self, user: &str, credential: &[u8]) -> Rewrite {
        let mut index = 1;
        if self
            .args
            .get(1)
            .is_some_and(|arg| !arg.is_empty() && arg.iter().all(|byte| byte.is_ascii_digit()))
        {
            index = 2;
        }
        let mut rewritten = false;
        while index < self.args.len() {
            if self.args[index].eq_ignore_ascii_case(b"AUTH") {
                // A second AUTH clause reaches the server after the one the agent checked, and the
                // server applies the last one. Refuse rather than forward a clause it never saw.
                if rewritten || index + 2 >= self.args.len() {
                    return Rewrite::UserMismatch;
                }
                if self.args[index + 1].as_slice() != user.as_bytes() {
                    return Rewrite::UserMismatch;
                }
                self.args[index + 1] = Zeroizing::new(user.as_bytes().to_vec());
                self.args[index + 2] = Zeroizing::new(credential.to_vec());
                rewritten = true;
                index += 3;
                continue;
            }
            if self.args[index].eq_ignore_ascii_case(b"SETNAME") {
                if index + 1 >= self.args.len() {
                    return Rewrite::UserMismatch;
                }
                index += 2;
                continue;
            }
            return Rewrite::UserMismatch;
        }
        if rewritten {
            Rewrite::Rewritten
        } else {
            Rewrite::Unchanged
        }
    }
}

pub async fn read_command<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Command>, Refusal> {
    let mut first = [0u8; 1];
    loop {
        match reader.read(&mut first).await {
            Ok(0) | Err(_) => return Ok(None),
            Ok(_) => {}
        }
        if first[0] != b'\r' {
            break;
        }
        let mut newline = [0u8; 1];
        reader
            .read_exact(&mut newline)
            .await
            .map_err(|_| Refusal::NonResp)?;
        if newline[0] != b'\n' {
            return Err(Refusal::NonResp);
        }
    }
    match first[0] {
        0x16 => return Err(Refusal::ClientTls),
        b'*' => {}
        _ => return Err(Refusal::NonResp),
    }
    let line = read_line(reader).await?;
    let count = number(&line).ok_or(Refusal::NonResp)?;
    if count > MAX_ELEMENTS {
        return Err(Refusal::NonResp);
    }
    let count = usize::try_from(count).map_err(|_| Refusal::NonResp)?;
    let mut used = 1 + line.len() + 2;
    let mut args = Vec::with_capacity(count.min(PREALLOCATED_ARGS));
    for _ in 0..count {
        let mut marker = [0u8; 1];
        reader
            .read_exact(&mut marker)
            .await
            .map_err(|_| Refusal::NonResp)?;
        if marker[0] != b'$' {
            return Err(Refusal::NonResp);
        }
        let line = read_line(reader).await?;
        let declared = number(&line).ok_or(Refusal::NonResp)?;
        let len = usize::try_from(declared).map_err(|_| Refusal::NonResp)?;
        used = used
            .saturating_add(1)
            .saturating_add(line.len())
            .saturating_add(2);
        if len > MAX_FRAME.saturating_sub(used).saturating_sub(2) {
            return Err(Refusal::NonResp);
        }
        let mut arg = Zeroizing::new(vec![0u8; len]);
        reader
            .read_exact(&mut arg)
            .await
            .map_err(|_| Refusal::NonResp)?;
        let mut terminator = [0u8; 2];
        reader
            .read_exact(&mut terminator)
            .await
            .map_err(|_| Refusal::NonResp)?;
        if terminator != *b"\r\n" {
            return Err(Refusal::NonResp);
        }
        used = used.saturating_add(len).saturating_add(2);
        args.push(arg);
    }
    Ok(Some(Command::from_zeroized(args)))
}

async fn read_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let mut line = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        if line.len() >= MAX_HEADER {
            return Err(Refusal::NonResp);
        }
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|_| Refusal::NonResp)?;
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
                return Ok(line);
            }
            return Err(Refusal::NonResp);
        }
        line.push(byte[0]);
    }
}

fn number(line: &[u8]) -> Option<u64> {
    if line.is_empty() || !line.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut value: u64 = 0;
    for &byte in line {
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    async fn command(bytes: &[u8]) -> Command {
        read_command(&mut &bytes[..]).await.unwrap().unwrap()
    }

    async fn refusal(bytes: &[u8]) -> Option<Refusal> {
        read_command(&mut &bytes[..]).await.err()
    }

    fn frame(args: &[&[u8]]) -> Vec<u8> {
        Command::new(args.iter().map(|arg| arg.to_vec()).collect())
            .encode()
            .to_vec()
    }

    fn strings(command: &Command) -> Vec<Vec<u8>> {
        command.args().iter().map(|arg| arg.to_vec()).collect()
    }

    #[tokio::test]
    async fn an_array_of_bulk_strings_round_trips() {
        let bytes = frame(&[b"SET", b"key", b"value"]);
        let command = command(&bytes).await;
        assert_eq!(
            strings(&command),
            vec![b"SET".to_vec(), b"key".to_vec(), b"value".to_vec()]
        );
        assert_eq!(command.encode().to_vec(), bytes);
    }

    #[tokio::test]
    async fn an_empty_array_is_a_frame() {
        let command = command(b"*0\r\n").await;
        assert!(command.args().is_empty());
        assert_eq!(command.encode().to_vec(), b"*0\r\n".to_vec());
    }

    #[tokio::test]
    async fn a_clean_end_of_stream_is_not_a_frame() {
        assert!(read_command(&mut &b""[..]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_inline_command_is_refused() {
        assert_eq!(refusal(b"PING\r\n").await, Some(Refusal::NonResp));
        assert_eq!(refusal(b"*1\r\nPING\r\n").await, Some(Refusal::NonResp));
    }

    #[tokio::test]
    async fn an_empty_line_between_frames_is_skipped() {
        let mut bytes = frame(&[b"PING"]);
        bytes.extend_from_slice(b"\r\n\r\n");
        bytes.extend_from_slice(&frame(&[b"GET", b"k"]));
        bytes.extend_from_slice(b"\r\n");
        let mut rest = &bytes[..];
        assert_eq!(
            strings(&read_command(&mut rest).await.unwrap().unwrap()),
            vec![b"PING".to_vec()]
        );
        assert_eq!(
            strings(&read_command(&mut rest).await.unwrap().unwrap()),
            vec![b"GET".to_vec(), b"k".to_vec()]
        );
        assert!(read_command(&mut rest).await.unwrap().is_none());
        assert_eq!(
            refusal(b"\r*1\r\n$4\r\nPING\r\n").await,
            Some(Refusal::NonResp)
        );
        assert_eq!(refusal(b"\r\nPING\r\n").await, Some(Refusal::NonResp));
    }

    #[tokio::test]
    async fn a_resp3_attribute_is_refused() {
        assert_eq!(
            refusal(b"|1\r\n$1\r\na\r\n$1\r\nb\r\n").await,
            Some(Refusal::NonResp)
        );
    }

    #[tokio::test]
    async fn a_non_bulk_element_is_refused() {
        assert_eq!(refusal(b"*1\r\n+PING\r\n").await, Some(Refusal::NonResp));
    }

    #[tokio::test]
    async fn a_negative_count_is_refused() {
        assert_eq!(refusal(b"*-1\r\n").await, Some(Refusal::NonResp));
        assert_eq!(refusal(b"*-2\r\n").await, Some(Refusal::NonResp));
    }

    #[tokio::test]
    async fn a_non_numeric_count_is_refused() {
        assert_eq!(refusal(b"*x\r\n").await, Some(Refusal::NonResp));
        assert_eq!(refusal(b"*+1\r\n").await, Some(Refusal::NonResp));
        assert_eq!(refusal(b"*\r\n").await, Some(Refusal::NonResp));
    }

    #[tokio::test]
    async fn an_oversized_header_is_refused() {
        let mut bytes = b"*".to_vec();
        bytes.extend_from_slice(&[b'1'; 200]);
        assert_eq!(refusal(&bytes).await, Some(Refusal::NonResp));
        assert_eq!(
            refusal(b"*1\r\n$999999999999999999999999999\r\n").await,
            Some(Refusal::NonResp)
        );
    }

    #[tokio::test]
    async fn the_element_limit_is_refused() {
        assert_eq!(
            refusal(format!("*{}\r\n", MAX_ELEMENTS + 1).as_bytes()).await,
            Some(Refusal::NonResp)
        );
    }

    #[tokio::test]
    async fn a_declared_element_beyond_the_frame_limit_is_refused_before_allocation() {
        assert_eq!(
            refusal(format!("*1\r\n${}\r\n", MAX_FRAME + 1).as_bytes()).await,
            Some(Refusal::NonResp)
        );
    }

    #[tokio::test]
    async fn a_truncated_frame_is_refused() {
        assert_eq!(refusal(b"*2\r\n$4\r\nAUTH").await, Some(Refusal::NonResp));
        assert_eq!(refusal(b"*1\r\n$4\r\nGETX").await, Some(Refusal::NonResp));
        assert_eq!(refusal(b"*1\r\n$4\r\nGET\n").await, Some(Refusal::NonResp));
    }

    #[tokio::test]
    async fn a_client_tls_hello_is_refused() {
        assert_eq!(refusal(b"\x16\x03\x01\x00").await, Some(Refusal::ClientTls));
    }

    #[tokio::test]
    async fn pipelined_frames_are_read_in_order() {
        let mut bytes = frame(&[b"PING"]);
        bytes.extend_from_slice(&frame(&[b"GET", b"k"]));
        let mut rest = &bytes[..];
        let first = read_command(&mut rest).await.unwrap().unwrap();
        let second = read_command(&mut rest).await.unwrap().unwrap();
        assert_eq!(strings(&first), vec![b"PING".to_vec()]);
        assert_eq!(strings(&second), vec![b"GET".to_vec(), b"k".to_vec()]);
    }

    fn auth(args: &[&[u8]]) -> Command {
        Command::new(args.iter().map(|arg| arg.to_vec()).collect())
    }

    #[test]
    fn auth_without_a_user_is_rewritten_to_the_credential() {
        let mut command = auth(&[b"AUTH", b"client-password"]);
        assert_eq!(
            command.rewrite_auth("default", false, b"credential"),
            Rewrite::Rewritten
        );
        assert_eq!(
            strings(&command),
            vec![b"AUTH".to_vec(), b"credential".to_vec()]
        );
    }

    #[test]
    fn auth_without_a_user_is_a_mismatch_when_the_binding_names_one() {
        let mut command = auth(&[b"AUTH", b"client-password"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::UserMismatch
        );
    }

    #[test]
    fn auth_with_a_user_is_rewritten_in_place() {
        let mut command = auth(&[b"AUTH", b"app", b"client-password"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Rewritten
        );
        assert_eq!(
            strings(&command),
            vec![b"AUTH".to_vec(), b"app".to_vec(), b"credential".to_vec()]
        );
    }

    #[test]
    fn another_user_is_a_mismatch() {
        let mut command = auth(&[b"AUTH", b"mallory", b"client-password"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::UserMismatch
        );
    }

    #[test]
    fn the_auth_clause_of_hello_is_rewritten_in_place() {
        let mut command = auth(&[
            b"HELLO",
            b"3",
            b"SETNAME",
            b"client",
            b"AUTH",
            b"app",
            b"client-password",
        ]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Rewritten
        );
        assert_eq!(
            strings(&command),
            vec![
                b"HELLO".to_vec(),
                b"3".to_vec(),
                b"SETNAME".to_vec(),
                b"client".to_vec(),
                b"AUTH".to_vec(),
                b"app".to_vec(),
                b"credential".to_vec(),
            ]
        );
    }

    #[test]
    fn hello_without_auth_is_unchanged() {
        let mut command = auth(&[b"HELLO", b"3"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Unchanged
        );
    }

    #[test]
    fn hello_without_a_protover_rewrites_its_auth_clause() {
        let mut command = auth(&[b"HELLO", b"AUTH", b"app", b"client-password"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Rewritten
        );
        assert_eq!(
            strings(&command),
            vec![
                b"HELLO".to_vec(),
                b"AUTH".to_vec(),
                b"app".to_vec(),
                b"credential".to_vec(),
            ]
        );
    }

    #[test]
    fn hello_setname_without_a_protover_is_unchanged() {
        let mut command = auth(&[b"HELLO", b"SETNAME", b"me"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Unchanged
        );
    }

    #[test]
    fn hello_with_a_protover_still_rewrites_its_auth_clause() {
        let mut command = auth(&[b"HELLO", b"3", b"AUTH", b"app", b"client-password"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Rewritten
        );
        assert_eq!(
            strings(&command),
            vec![
                b"HELLO".to_vec(),
                b"3".to_vec(),
                b"AUTH".to_vec(),
                b"app".to_vec(),
                b"credential".to_vec(),
            ]
        );
    }

    #[test]
    fn hello_auth_for_another_user_is_a_mismatch() {
        let mut command = auth(&[b"HELLO", b"3", b"AUTH", b"mallory", b"client-password"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::UserMismatch
        );
    }

    #[test]
    fn hello_auth_without_a_password_is_a_mismatch() {
        let mut command = auth(&[b"HELLO", b"3", b"AUTH", b"app"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::UserMismatch
        );
    }

    #[test]
    fn hello_with_an_unknown_option_is_a_mismatch() {
        let mut command = auth(&[b"HELLO", b"3", b"WHOAMI", b"app", b"AUTH", b"app", b"x"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::UserMismatch
        );
    }

    #[test]
    fn an_auth_name_appearing_as_a_setname_value_is_not_an_auth_clause() {
        let mut command = auth(&[b"HELLO", b"3", b"SETNAME", b"AUTH"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Unchanged
        );
    }

    #[test]
    fn a_second_auth_clause_is_a_mismatch() {
        for mut command in [
            auth(&[
                b"HELLO",
                b"3",
                b"AUTH",
                b"app",
                b"client-password",
                b"AUTH",
                b"mallory",
                b"client-password",
            ]),
            auth(&[
                b"HELLO",
                b"AUTH",
                b"app",
                b"client-password",
                b"AUTH",
                b"app",
                b"client-password",
            ]),
        ] {
            assert_eq!(
                command.rewrite_auth("app", true, b"credential"),
                Rewrite::UserMismatch
            );
        }
    }

    #[test]
    fn a_token_after_the_auth_clause_is_a_mismatch() {
        let mut command = auth(&[
            b"HELLO",
            b"3",
            b"AUTH",
            b"app",
            b"client-password",
            b"WHOAMI",
        ]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::UserMismatch
        );
    }

    #[test]
    fn setname_after_the_auth_clause_is_rewritten() {
        let mut command = auth(&[
            b"HELLO",
            b"3",
            b"AUTH",
            b"app",
            b"client-password",
            b"SETNAME",
            b"client",
        ]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Rewritten
        );
        assert_eq!(
            strings(&command),
            vec![
                b"HELLO".to_vec(),
                b"3".to_vec(),
                b"AUTH".to_vec(),
                b"app".to_vec(),
                b"credential".to_vec(),
                b"SETNAME".to_vec(),
                b"client".to_vec(),
            ]
        );
    }

    #[test]
    fn other_commands_are_unchanged() {
        let mut command = auth(&[b"SELECT", b"1"]);
        assert_eq!(
            command.rewrite_auth("app", true, b"credential"),
            Rewrite::Unchanged
        );
    }
}
