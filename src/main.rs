use std::{io::Write, path::PathBuf, net::SocketAddr, str::FromStr, time::Instant, sync::Arc};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct SkipServerVerification;
impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn server(path: PathBuf) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async move {
        let (endpoint, mut incoming) = quinn::Endpoint::server({
            let cert = rcgen::generate_simple_self_signed(vec!["quictransfer".into()]).unwrap();
            let cert_der = cert.serialize_der().unwrap();
            let priv_key = cert.serialize_private_key_der();
            let priv_key = rustls::PrivateKey(priv_key);
            let cert_chain = vec![rustls::Certificate(cert_der)];
            quinn::ServerConfig::with_single_cert(cert_chain, priv_key).unwrap()
        }, SocketAddr::from_str("0.0.0.0:0").unwrap()).unwrap();

        println!("Listening on {}", endpoint.local_addr().unwrap());

        let mut f = tokio::fs::File::open(path).await.unwrap();
        let size = f.metadata().await.unwrap().len();

        let connection = incoming.next().await.unwrap();
        let connection = connection.await.unwrap();
        let mut tx = connection.connection.open_uni().await.unwrap();

        tx.write_u64_le(size).await.unwrap();

        let start = Instant::now();
        tokio::io::copy(&mut f, &mut tx).await.unwrap();
        let start = start.elapsed();
        println!("File sent in {start:?} ({} bytes/s)", size as f64 / start.as_secs_f64());

        endpoint.wait_idle().await;
    });
}

fn client() {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async move {
        let ip_port = {
            print!("Enter peer IP address and port: ");
            std::io::stdout().lock().flush().unwrap();

            let mut addr = String::new();
            std::io::stdin().read_line(&mut addr).unwrap();

            SocketAddr::from_str(addr.trim()).unwrap()
        };

        let mut endpoint = quinn::Endpoint::client(SocketAddr::from_str("0.0.0.0:0").unwrap()).unwrap();

        endpoint.set_default_client_config(quinn::ClientConfig::new(
            Arc::new(rustls::ClientConfig::builder()
                .with_cipher_suites(&[rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256])
                .with_safe_default_kx_groups()
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth())
        ));

        let mut connection = endpoint.connect(ip_port, "quictransfer").unwrap().await.unwrap();
        let mut rx = connection.uni_streams.next().await.unwrap().unwrap();

        let size = rx.read_u64_le().await.unwrap();

        let mut f = tokio::fs::File::create("received.bin").await.unwrap();

        let start = Instant::now();
        tokio::io::copy(&mut rx.take(size), &mut f).await.unwrap();
        let start = start.elapsed();
        println!("File received in {start:?} ({} bytes/s)", size as f64 / start.as_secs_f64());

        connection.connection.close(quinn::VarInt::from_u32(0), &[]);
        endpoint.wait_idle().await;
    });
}

fn main() {
    let path = {
        print!("Enter file path or press enter to receive: ");
        std::io::stdout().lock().flush().unwrap();

        let mut path = String::new();
        std::io::stdin().read_line(&mut path).unwrap();

        let path = path.trim();

        if path.is_empty() {
            None
        } else {
            Some(PathBuf::from(path))
        }
    };

    if let Some(path) = path {
        server(path);
    } else {
        client();
    }
}
