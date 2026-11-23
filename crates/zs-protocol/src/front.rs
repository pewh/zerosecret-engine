use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, tcp};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream, unix};

use crate::{Caller, ListenSpec};

pub struct FrontListener {
    socket: Socket,
    local: ListenSpec,
}

enum Socket {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl FrontListener {
    pub async fn bind(spec: &ListenSpec) -> io::Result<Self> {
        match spec {
            ListenSpec::Tcp(addr) => {
                let listener = TcpListener::bind(addr).await?;
                Ok(Self {
                    local: ListenSpec::Tcp(listener.local_addr()?),
                    socket: Socket::Tcp(listener),
                })
            }
            #[cfg(unix)]
            ListenSpec::Unix(path) => {
                use std::os::unix::fs::PermissionsExt;

                let listener = UnixListener::bind(path)?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                Ok(Self {
                    local: spec.clone(),
                    socket: Socket::Unix(listener),
                })
            }
            #[cfg(not(unix))]
            ListenSpec::Unix(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a Unix socket listener needs a Unix host",
            )),
        }
    }

    pub fn local(&self) -> &ListenSpec {
        &self.local
    }

    pub async fn accept(&self) -> io::Result<(ClientStream, Caller)> {
        match &self.socket {
            Socket::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                let caller = Caller::tcp(peer, stream.local_addr());
                Ok((ClientStream::Tcp(stream), caller))
            }
            #[cfg(unix)]
            Socket::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                let uid = stream.peer_cred().ok().map(|cred| cred.uid());
                Ok((ClientStream::Unix(stream), Caller::Unix { uid }))
            }
        }
    }
}

pub enum ClientStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

pub enum ClientReadHalf {
    Tcp(tcp::OwnedReadHalf),
    #[cfg(unix)]
    Unix(unix::OwnedReadHalf),
}

pub enum ClientWriteHalf {
    Tcp(tcp::OwnedWriteHalf),
    #[cfg(unix)]
    Unix(unix::OwnedWriteHalf),
}

impl ClientStream {
    pub fn into_split(self) -> (ClientReadHalf, ClientWriteHalf) {
        match self {
            Self::Tcp(stream) => {
                let (read, write) = stream.into_split();
                (ClientReadHalf::Tcp(read), ClientWriteHalf::Tcp(write))
            }
            #[cfg(unix)]
            Self::Unix(stream) => {
                let (read, write) = stream.into_split();
                (ClientReadHalf::Unix(read), ClientWriteHalf::Unix(write))
            }
        }
    }
}

macro_rules! on_inner {
    ($value:expr, $inner:ident => $body:expr) => {
        match $value {
            Self::Tcp($inner) => $body,
            #[cfg(unix)]
            Self::Unix($inner) => $body,
        }
    };
}

macro_rules! async_read {
    ($type:ty) => {
        impl AsyncRead for $type {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                on_inner!(self.get_mut(), inner => Pin::new(inner).poll_read(cx, buf))
            }
        }
    };
}

macro_rules! async_write {
    ($type:ty) => {
        impl AsyncWrite for $type {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                on_inner!(self.get_mut(), inner => Pin::new(inner).poll_write(cx, buf))
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                on_inner!(self.get_mut(), inner => Pin::new(inner).poll_write_vectored(cx, bufs))
            }

            fn is_write_vectored(&self) -> bool {
                on_inner!(self, inner => inner.is_write_vectored())
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                on_inner!(self.get_mut(), inner => Pin::new(inner).poll_flush(cx))
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                on_inner!(self.get_mut(), inner => Pin::new(inner).poll_shutdown(cx))
            }
        }
    };
}

async_read!(ClientStream);
async_read!(ClientReadHalf);
async_write!(ClientStream);
async_write!(ClientWriteHalf);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn owned_stream<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>() {}
    fn owned_read<T: AsyncRead + Unpin + Send + 'static>() {}
    fn owned_write<T: AsyncWrite + Unpin + Send + 'static>() {}

    #[test]
    fn a_client_stream_and_its_halves_are_owned_async_streams() {
        owned_stream::<ClientStream>();
        owned_read::<ClientReadHalf>();
        owned_write::<ClientWriteHalf>();
    }

    async fn carries_bytes<C: AsyncRead + AsyncWrite + Unpin>(
        mut stream: ClientStream,
        mut client: C,
    ) {
        client.write_all(b"ping").await.unwrap();
        let mut ping = [0u8; 4];
        stream.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"ping");
        stream.write_all(b"pong").await.unwrap();
        let mut pong = [0u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");

        let (mut read, mut write) = stream.into_split();
        client.write_all(b"after split").await.unwrap();
        let mut after = [0u8; 11];
        read.read_exact(&mut after).await.unwrap();
        assert_eq!(&after, b"after split");
        write.write_all(b"bye").await.unwrap();
        write.shutdown().await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"bye");
    }

    #[tokio::test]
    async fn a_tcp_accept_gives_the_peer_and_local_addresses() {
        let spec = ListenSpec::Tcp((Ipv4Addr::LOCALHOST, 0).into());
        let front = FrontListener::bind(&spec).await.unwrap();
        let ListenSpec::Tcp(bound) = front.local().clone() else {
            panic!("a TCP listener reports a TCP address");
        };
        assert_eq!(bound.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(bound.port(), 0);
        let client = tokio::net::TcpStream::connect(bound).await.unwrap();
        let (stream, caller) = front.accept().await.unwrap();
        assert_eq!(
            caller,
            Caller::Tcp {
                peer: client.local_addr().unwrap(),
                local: bound,
            }
        );
        carries_bytes(stream, client).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_unix_accept_gives_the_user_id_of_the_peer() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("front.sock");
        let spec = ListenSpec::Unix(path.clone());
        let front = FrontListener::bind(&spec).await.unwrap();
        assert_eq!(front.local(), &spec);
        let client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (stream, caller) = front.accept().await.unwrap();
        let own = std::fs::metadata(dir.path()).unwrap().uid();
        assert_eq!(caller, Caller::Unix { uid: Some(own) });
        carries_bytes(stream, client).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_unix_socket_file_has_mode_0600() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("front.sock");
        let _front = FrontListener::bind(&ListenSpec::Unix(path.clone()))
            .await
            .unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.mode() & 0o777, 0o600, "{:o}", meta.mode());
    }
}
