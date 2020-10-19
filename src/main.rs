use ajson;
use argh::FromArgs;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

#[derive(FromArgs)]
/// A mini TLS-based proxy dedicated to NAT passthrough.
struct Options {
    /// json config file
    #[argh(positional)]
    config: PathBuf,
}

struct InnerHost {
    local_port: u32,
    exposed_port: u32,
}

struct Config {
    server_addr: String,
    server_port: u32,
    inner_hosts: Vec<InnerHost>,
    certs: Vec<Certificate>,
    keys: Vec<PrivateKey>,
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid Certificate!"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid Private Key!"))
}

fn load_config() -> io::Result<Config> {
    let options: Options = argh::from_env();
    let file = File::open(&options.config)?;

    if let Some(json_obj) = ajson::parse_from_read(file) {
        let server_addr = json_obj.get("server_addr").unwrap().to_string();
        let server_port = json_obj.get("server_port").unwrap().to_u64() as u32;
        let ih_num = json_obj.get("inner_hosts.#").unwrap().to_u64() as u32;
        let mut inner_hosts = Vec::<InnerHost>::new();
        for i in 0..ih_num {
            let inner_host = InnerHost {
                local_port: json_obj
                    .get(format!("inner_hosts.{}.local_port", i).as_str())
                    .unwrap()
                    .to_u64() as u32,
                exposed_port: json_obj
                    .get(format!("inner_hosts.{}.exposed_port", i).as_str())
                    .unwrap()
                    .to_u64() as u32,
            };
            inner_hosts.push(inner_host);
        }
        let cert_path = json_obj.get("cert_path").unwrap().to_string();
        let key_path = json_obj.get("key_path").unwrap().to_string();
        let certs = load_certs(&Path::new(&cert_path))?;
        let keys = load_keys(&Path::new(&key_path))?;

        let config = Config {
            server_addr: server_addr,
            server_port: server_port,
            inner_hosts: inner_hosts,
            certs: certs,
            keys: keys,
        };

        Ok(config)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid Configuration File!",
        ))
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = load_config()?;

    Ok(()) as io::Result<()>
}
