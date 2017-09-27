use tokio_core::net;

pub struct TcpStream {
    pub tcp_stream: net::TcpStream,
}
