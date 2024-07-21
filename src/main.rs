use std::net::IpAddr;

use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use defguard_wireguard_rs::{net::IpAddrMask, WireguardInterfaceApi};
use display_error_chain::DisplayErrorChain;
use snafu::{OptionExt, ResultExt};
use wireguard_simple_manager::{
    config::Config,
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
        /// Desired IP address.
        #[clap(long)]
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

    let mut peers_meta =
        PeersMeta::load(&config.peers).whatever_context("Can't load meta information file")?;

    tracing::debug!("Loaded peers meta:\n{peers_meta}");

    let api = defguard_wireguard_rs::WGApi::new(config.interface_name, false)
        .whatever_context("Can't init wireguard API")?;
    let host = api
        .read_interface_data()
        .whatever_context("Can't read interface data")?;

    for (key, peer) in &host.peers {
        let key = PublicKey::from(key);
        if let Some(meta) = peers_meta.peer(&key) {
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

    for peer in peers_meta.peers() {
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
                if let Some(meta) = peers_meta.peer(&key) {
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

                if let Some(existing_peer) = peers_meta.peer_by_ip(ip) {
                    snafu::whatever!("Peer with {ip} address already exists:\n{existing_peer}");
                }
                ip
            } else {
                let last_ip = peers_meta.last_ip().unwrap_or(config.network_mask.ip);
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
            writeln!(
                peer_config_file,
                "# VPN {}\n# Peer name: {name}",
                config.name
            )
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

            peers_meta
                .add_peer(new_peer)
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

                if let Err(e) = peers_meta.save().whatever_context("Save meta information") {
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
            if let Some(info) = peers_meta.remove_peer(&public_key) {
                tracing::info!("Removing peer\n{info}");
                if !dry_run {
                    peers_meta
                        .save()
                        .whatever_context("Save meta information")?;
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
