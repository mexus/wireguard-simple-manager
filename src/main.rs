use std::net::IpAddr;

use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use defguard_wireguard_rs::{net::IpAddrMask, WireguardInterfaceApi};
use display_error_chain::DisplayErrorChain;
use snafu::{OptionExt, ResultExt, Snafu};
use wireguard_simple_manager::{
    ip_utils::{check_ip, next_ip},
    peers_meta::{PeerMeta, PeersMeta},
    wg_key::{PresharedKey, PrivateKey, PublicKey},
};

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

        /// When set, no changes are made to either the wireguard or meta
        /// information.
        #[clap(long)]
        dry_run: bool,
    },
    /// Lists the wireguard peers.
    ListPeers,
    /// Removes a wireguard peer.
    RemovePeer {
        /// Public key of the peer to remove.
        public_key: PublicKey,

        /// When set, no changes are made to either the wireguard or meta
        /// information.
        #[clap(long)]
        dry_run: bool,
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

    /// External VPN IP or DNS address.
    external_address: String,

    /// External VPN port.
    external_port: u32,

    /// Path to the peers meta information.
    meta: Utf8PathBuf,

    /// Name of the wireguard interface.
    #[serde(rename = "interface")]
    interface_name: String,

    /// VPN network mask.
    #[serde(with = "serde_ip_addr_mask")]
    network_mask: IpAddrMask,
}

#[derive(PartialEq, Eq)]
#[repr(transparent)]
struct WgKey(defguard_wireguard_rs::key::Key);

impl std::str::FromStr for WgKey {
    type Err = base64_21::DecodeError;

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
    tracing::debug!("Loaded config:\n{config:#?}");

    let mut meta =
        PeersMeta::load(&config.meta).whatever_context("Can't load meta information file")?;

    tracing::debug!("Loaded peers meta:\n{meta:#?}");

    let api = defguard_wireguard_rs::WGApi::new(config.interface_name, false)
        .whatever_context("Can't init wireguard API")?;
    let host = api
        .read_interface_data()
        .whatever_context("Can't read interface data")?;

    for (key, peer) in &host.peers {
        let key = PublicKey::from(key);
        if let Some(meta) = meta.peer(&key) {
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

    for peer in meta.peers() {
        let key = peer.public_key.into();
        if !host.peers.contains_key(&key) {
            tracing::warn!(
                "Peer {key} is listed in the meta information file, \
                 but isn't registered within the wireguard!"
            );
        }
    }

    match command {
        Commands::ListPeers => {
            for (key, peer) in &host.peers {
                let key = PublicKey::from(key);
                if let Some(meta) = meta.peer(&key) {
                    let last_handshake = peer.last_handshake.map(time::OffsetDateTime::from);
                    tracing::info!(
                        "{key}, {} ({:?}), ip: {:?}, last handshake: {:?}",
                        meta.name,
                        meta.comment,
                        meta.ip,
                        last_handshake
                    );
                }
            }
        }
        Commands::AddPeer {
            name,
            comment,
            ip,
            output,
            dry_run,
        } => {
            let host_public_key = {
                let host_private_key: PrivateKey = host
                    .private_key
                    .whatever_context("Host private key is unaccessible")?
                    .into();
                host_private_key.public()
            };

            let mut output_file;
            let mut output_stdout;

            let output = if dry_run {
                output_stdout = std::io::stdout();
                &mut output_stdout
            } else {
                let output_path = output
                    .unwrap_or_else(|| Utf8PathBuf::from(format!("{}_{name}.conf", config.name)));
                output_file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(output_path)
                    .whatever_context("Can't open output file")?;
                &mut output_file as &mut dyn std::io::Write
            };

            let ip = if let Some(ip) = ip {
                snafu::ensure_whatever!(
                    check_ip(ip, &config.network_mask),
                    "The provided IP address doesn't match the network"
                );
                ip
            } else {
                let last_ip = meta.last_ip().unwrap_or(config.network_mask.ip);
                next_ip(last_ip, &config.network_mask)
                    .whatever_context("Can't calculate next IP")?
            };

            let secret_key = PrivateKey::random(&mut rand::rngs::OsRng);
            let public_key = secret_key.public();
            tracing::info!(
                "Peer public: {public_key}\n\
                 IP: {ip}",
            );

            let preshared_key = PresharedKey::random(&mut rand::rngs::OsRng);

            let endpoint_name = &config.external_address;
            let endpoint_port = &config.external_port;
            let network_mask = &config.network_mask;

            use std::fmt::Write as _;
            let mut peer_config_file = String::new();
            writeln!(peer_config_file, "#{}\n# {name}", config.name)
                .expect("Write to string doesn't fail");
            if let Some(comment) = &comment {
                writeln!(peer_config_file, "{comment}").expect("Write to string doesn't fail");
            }

            write!(
                peer_config_file,
                "\
[Interface]
Address = {ip}/32
PrivateKey = {secret_key}

[Peer]
PublicKey = {host_public_key}
PresharedKey = {preshared_key}
AllowedIPs = {network_mask}
Endpoint = {endpoint_name}:{endpoint_port}
PersistentKeepalive = 25
",
            )
            .expect("Write to string doesn't fail");

            let new_peer = PeerMeta {
                comment,
                name,
                ip,
                public_key,
            };

            meta.add_peer(new_peer)
                .whatever_context("Adding a new peer")?;

            let wg_peer = defguard_wireguard_rs::host::Peer {
                public_key: public_key.into(),
                preshared_key: Some(preshared_key.clone().into()),
                allowed_ips: vec![IpAddrMask::new(ip, config.network_mask.cidr)],
                ..Default::default()
            };

            if !dry_run {
                api.configure_peer(&wg_peer)
                    .whatever_context("Can't add the WG peer")?;

                if let Err(e) = meta.save().whatever_context("Save meta information") {
                    tracing::warn!(
                        "Unable to save the meta. \
                     Remove the peer from the wireguard"
                    );
                    if let Err(e) = api.remove_peer(&public_key.into()) {
                        tracing::error!(
                            "Unable to remove the peer from the wireguard: {}",
                            DisplayErrorChain::new(&e)
                        );
                    }
                    return Err(e);
                }
            }

            if let Err(e) = output.write_all(peer_config_file.as_bytes()) {
                let e = DisplayErrorChain::new(e);
                tracing::error!(
                    "Unable to write peer configuration file: {e}.\n\
                     Print file to stdout instead:\n"
                );
                println!("{peer_config_file}");
            }
            tracing::info!("Peer successfully added");
        }
        Commands::RemovePeer {
            public_key,
            dry_run,
        } => {
            if let Some(info) = meta.remove_peer(&public_key) {
                tracing::info!("Removing peer\n{info}");
                if !dry_run {
                    meta.save().whatever_context("Save meta information")?;
                    api.remove_peer(&public_key.into())
                        .whatever_context("Can't remove the peer from the wireguard")?;
                }

                tracing::info!("Peer successfully removed");
            } else {
                snafu::whatever!("The peer doesn't exist!");
            }
        }
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
