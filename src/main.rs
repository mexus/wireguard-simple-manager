use std::net::IpAddr;

use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use curve25519_dalek::EdwardsPoint;
use defguard_wireguard_rs::{net::IpAddrMask, WireguardInterfaceApi};
use indexmap::IndexMap;
use rand::RngCore;
use snafu::{OptionExt, ResultExt, Snafu};

/// A very simple wireguard manager tool.
///
/// Run as root!
#[derive(Debug, Parser)]
struct Args {
    /// Path to the configuration file.
    #[clap(long, default_value = "config.toml")]
    config: Utf8PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Adds a wireguard peer.
    AddPeer {
        /// Peer user name.
        name: String,
        /// Comment.
        comment: Option<String>,
        /// IP address mask.
        #[clap(value_parser = parse_ip_mask)]
        ip: Option<IpAddr>,
        /// Output file name where peer information is stored. If not provided,
        /// the file name is derived from the network name and client's name.
        #[clap(short, long)]
        output: Option<Utf8PathBuf>,
    },
    /// Lists the wireguard peers.
    ListPeers,
    /// Removes a wireguard peer.
    RemovePeer {
        /// Public key of the peer to remove.
        public_key: String,
    },
}

#[test]
fn check_args() {
    <Args as clap::CommandFactory>::command().debug_assert();
}

#[derive(Debug, serde::Deserialize)]
struct Config {
    /// Name of the network.
    name: String,

    /// Path to the peers meta information.
    meta: Utf8PathBuf,

    /// Name of the wireguard interface.
    #[serde(rename = "interface")]
    interface_name: String,

    /// VPN network mask.
    #[serde(with = "serde_ip_addr_mask")]
    network_mask: IpAddrMask,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PeerMeta {
    /// Full name of the peer.
    full_name: String,
    /// A comment regarding the peer.
    comment: Option<String>,
    /// Public key.
    public_key: WgKey,
    /// IP address within the private network.
    ip: IpAddr,
}

#[derive(PartialEq, Eq)]
#[repr(transparent)]
struct WgKey(defguard_wireguard_rs::key::Key);

impl std::str::FromStr for WgKey {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        defguard_wireguard_rs::key::Key::try_from(s).map(WgKey)
    }
}

impl std::hash::Hash for WgKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<'a> From<&'a defguard_wireguard_rs::key::Key> for &'a WgKey {
    fn from(value: &'a defguard_wireguard_rs::key::Key) -> Self {
        // It is safe because of the repr(transparent).
        unsafe { std::mem::transmute(value) }
    }
}

impl std::borrow::Borrow<defguard_wireguard_rs::key::Key> for WgKey {
    fn borrow(&self) -> &defguard_wireguard_rs::key::Key {
        &self.0
    }
}

impl std::fmt::Debug for WgKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl std::fmt::Display for WgKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl serde::Serialize for WgKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for WgKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let key = defguard_wireguard_rs::key::Key::try_from(key.as_str())
            .map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(Self(key))
    }
}

#[snafu::report]
fn main() -> Result<(), snafu::Whatever> {
    run()
}

fn run() -> Result<(), snafu::Whatever> {
    let Args { config, command } = Args::parse();

    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::INFO)
        .init();

    let config: Config = {
        let data =
            std::fs::read_to_string(config).whatever_context("Can't read configuration file")?;
        toml::from_str(&data).whatever_context("Can't parse configuration file")?
    };
    // tracing::info!("Loaded config:\n{config:#?}");

    let mut meta: IndexMap<WgKey, PeerMeta> = {
        let data = std::fs::read_to_string(&config.meta)
            .whatever_context("Can't read configuration file")?;
        toml::from_str(&data).whatever_context("Can't parse configuration file")?
    };

    // tracing::info!("Loaded peers meta:\n{meta:#?}");

    let api = defguard_wireguard_rs::WGApi::new(config.interface_name, false)
        .whatever_context("Can't init wireguard API")?;
    let host = api
        .read_interface_data()
        .whatever_context("Can't read interface data")?;

    for (key, peer) in &host.peers {
        if let Some(meta) = meta.get(<&WgKey>::from(key)) {
            let ip = meta.ip;
            let ip_match = peer
                .allowed_ips
                .iter()
                .any(|allowed_ip| check_ip(ip, allowed_ip));
            if !ip_match {
                tracing::warn!(
                    {%key},
                    "The assigned IP address {ip} \
                     is not within the wireguard allowed IPs {:?}",
                     peer.allowed_ips
                );
            }
        } else {
            tracing::warn!(
                "Peer {key} is registered within the wireguard but \
                 meta information on it is missing"
            );
        }
    }

    for key in meta.keys() {
        if !host.peers.contains_key(&key.0) {
            tracing::warn!(
                "Peer {key} is listed in the meta information file, \
                 but isn't registered within the wireguard!"
            );
        }
    }

    match command {
        Commands::ListPeers => {
            for (key, peer) in &host.peers {
                if let Some(meta) = meta.get(<&WgKey>::from(key)) {
                    tracing::info!(
                        "{key}, {} ({:?}), ip: {:?}, last handshake: {:?}",
                        meta.full_name,
                        meta.comment,
                        meta.ip,
                        peer.last_handshake
                    );
                }
            }
        }
        Commands::AddPeer {
            name,
            comment,
            ip,
            output,
        } => {
            let output =
                output.unwrap_or_else(|| Utf8PathBuf::from(format!("{}_{name}.conf", config.name)));
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)
                .whatever_context("Can't open output file")?;
            let ip = if let Some(ip) = ip {
                snafu::ensure_whatever!(
                    check_ip(ip, &config.network_mask),
                    "The provided IP address doesn't match the network"
                );
                ip
            } else {
                let last_ip = meta
                    .values()
                    .map(|meta| meta.ip)
                    .max()
                    .unwrap_or(config.network_mask.ip);
                next_ip(last_ip, &config.network_mask)
                    .whatever_context("Can't calculate next IP")?
            };
            let mut secret_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret_bytes[..]);
            let secret_key = defguard_wireguard_rs::key::Key::new(secret_bytes);

            let public_bytes = EdwardsPoint::mul_base_clamped(secret_bytes)
                .to_montgomery()
                .to_bytes();
            let public_key = defguard_wireguard_rs::key::Key::new(public_bytes);
            tracing::info!(
                "Peer secret: {secret_key}\n\
                 Peer public: {public_key}\n\
                 IP: {ip}",
            );

            let mut preshared_key_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut preshared_key_bytes[..]);
            let preshared_key = defguard_wireguard_rs::key::Key::new(preshared_key_bytes);

            let new_peer = PeerMeta {
                comment,
                full_name: name,
                ip,
                public_key: WgKey(public_key.clone()),
            };

            let wg_peer = defguard_wireguard_rs::host::Peer {
                public_key: public_key.clone(),
                preshared_key: Some(preshared_key),
                allowed_ips: vec![IpAddrMask::new(ip, config.network_mask.cidr)],
                ..Default::default()
            };

            api.configure_peer(&wg_peer)
                .whatever_context("Can't add the WG peer")?;

            meta.insert(WgKey(public_key.clone()), new_peer);

            todo!(
                "Update the meta, if fails, remove the peer.\n\
                 Then print the wg config file, if fails -- print to stdout"
            );

            // api.remove_peer(&public_key);
        }
        Commands::RemovePeer { .. } => todo!(),
    }

    Ok(())
}

#[derive(Debug, Snafu)]
enum ParseIpMaskError {
    /// The IP part is missing.
    #[snafu(display("The IP part is missing"))]
    MissingIp,

    /// Unable to parse the IP part.
    #[snafu(display("Unable to parse the IP part: {ip:?}"))]
    ParseIp {
        /// The stringified IP.
        ip: String,
        /// Source error.
        source: std::net::AddrParseError,
    },

    /// Unable to parse the CIDR part.
    #[snafu(display("Unable to parse the CIDR part: {cidr:?}"))]
    ParseCidr {
        /// The stringified cidr.
        cidr: String,
        /// Source error.
        source: std::num::ParseIntError,
    },
}

fn parse_ip_mask(input: &str) -> Result<IpAddrMask, ParseIpMaskError> {
    let mut parts = input.split('/');

    let ip = parts.next().context(MissingIpSnafu)?;

    let ip: std::net::IpAddr = ip.parse().context(ParseIpSnafu { ip })?;

    let cidr: u8 = parts
        .next()
        .map(|cidr| cidr.parse().context(ParseCidrSnafu { cidr }))
        .unwrap_or_else(|| Ok(if ip.is_ipv4() { 32 } else { 128 }))?;

    Ok(IpAddrMask { cidr, ip })
}

mod serde_ip_addr_mask {
    use defguard_wireguard_rs::net::IpAddrMask;
    // use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
    use serde::{de::Error as _, Deserialize, Deserializer};

    // /// Serializes the ip address with a mask.
    // pub fn serialize<S>(ip_mask: &IpAddrMask, serializer: S) -> Result<S::Ok, S::Error>
    // where
    //     S: Serializer,
    // {
    //     let stringified = ip_mask.to_string();
    //     stringified.serialize(serializer)
    // }

    /// Deserializes an ip address with a mask.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<IpAddrMask, D::Error>
    where
        D: Deserializer<'de>,
    {
        let stringified = String::deserialize(deserializer)?;
        super::parse_ip_mask(&stringified)
            .map_err(|e| format!("Parse {stringified:?}: {e}"))
            .map_err(D::Error::custom)
    }
    // /// Serializes the ip address with a mask.
    // pub fn serialize<S>(ip_mask: &[IpAddrMask], serializer: S) -> Result<S::Ok, S::Error>
    // where
    //     S: Serializer,
    // {
    //     let stringified = ip_mask.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();
    //     stringified.serialize(serializer)
    // }

    // /// Deserializes an ip address with a mask.
    // pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<IpAddrMask>, D::Error>
    // where
    //     D: Deserializer<'de>,
    // {
    //     let stringified = Vec::<String>::deserialize(deserializer)?;
    //     let mut output = vec![];
    //     for stringified in stringified {
    //         output.push(
    //             super::parse_ip_mask(&stringified)
    //                 .map_err(|e| format!("Parse {stringified:?}: {e}"))
    //                 .map_err(D::Error::custom)?,
    //         );
    //     }

    //     Ok(output)
    // }
}

/// Checks whether IP belongs to a mask.
fn check_ip(ip: IpAddr, mask: &IpAddrMask) -> bool {
    macro_rules! check {
        ($ip:expr, $mask_ip:expr, $cidr:expr, $int_type:ty) => {{
            let netmask = if u32::from($cidr) == <$int_type>::BITS {
                <$int_type>::MAX
            } else {
                <$int_type>::MAX - (2 as $int_type).pow(u32::from($cidr)) + 1
            };
            let ip_bits = <$int_type>::from($ip) & netmask;
            let network_bits = <$int_type>::from($mask_ip) & netmask;
            ip_bits == network_bits
        }};
    }
    match (ip, mask.ip) {
        (IpAddr::V4(v4), IpAddr::V4(mask_v4)) => {
            check!(v4, mask_v4, mask.cidr, u32)
        }
        (IpAddr::V6(v6), IpAddr::V6(mask_v6)) => {
            check!(v6, mask_v6, mask.cidr, u128)
        }
        _ => {
            // Mismatch!
            false
        }
    }
}

#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(display("Network exhausted"))]
struct SubNetworkExhausted {}

fn next_ip(last_ip: IpAddr, mask: &IpAddrMask) -> Result<IpAddr, SubNetworkExhausted> {
    macro_rules! next {
        ($ip:expr, $int_type:ty) => {
            <$int_type>::from($ip)
                .checked_add(1)
                .context(SubNetworkExhaustedSnafu)?
                .into()
        };
    }
    let next = match last_ip {
        IpAddr::V4(ip) => IpAddr::V4(next!(ip, u32)),
        IpAddr::V6(ip) => IpAddr::V6(next!(ip, u128)),
    };
    snafu::ensure!(check_ip(next, mask), SubNetworkExhaustedSnafu);
    Ok(next)
}

#[test]
fn check_ip_test() {
    assert!(check_ip(
        "172.17.0.5".parse().unwrap(),
        &"172.17.0.5/16".parse().unwrap(),
    ));
    assert!(check_ip(
        "172.17.0.5".parse().unwrap(),
        &"172.17.0.0/16".parse().unwrap(),
    ));
    assert!(!check_ip(
        "172.18.0.5".parse().unwrap(),
        &"172.17.0.5/16".parse().unwrap(),
    ));
}

#[test]
fn check_next_ip() {
    assert_eq!(
        next_ip(
            "172.17.0.5".parse().unwrap(),
            &"172.17.0.0/16".parse().unwrap(),
        ),
        Ok("172.17.0.6".parse().unwrap())
    );
    assert_eq!(
        next_ip(
            "172.17.0.255".parse().unwrap(),
            &"172.17.0.0/16".parse().unwrap(),
        ),
        Ok("172.17.1.0".parse().unwrap())
    );
    assert_eq!(
        next_ip(
            "172.17.255.254".parse().unwrap(),
            &"172.17.0.0/16".parse().unwrap(),
        ),
        Ok("172.17.255.255".parse().unwrap())
    );
    assert_eq!(
        next_ip(
            "172.17.255.255".parse().unwrap(),
            &"172.17.0.0/16".parse().unwrap(),
        ),
        Err(SubNetworkExhausted {})
    );
}
