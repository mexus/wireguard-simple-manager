use std::{net::IpAddr, os::unix::fs::OpenOptionsExt, time::Duration};

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
        /// the file name is derived from the network name.
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

    let api = defguard_wireguard_rs::WGApi::new(config.interface_name.clone(), false)
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
            let mut peers = host.peers.iter().collect::<Vec<_>>();
            peers.sort_unstable_by_key(|(_key, peer)| {
                (
                    !peer_is_active(peer),
                    peer.allowed_ips.first().map(|addr_mask| addr_mask.ip),
                )
            });
            let first_inactive = peers.partition_point(|(_key, peer)| peer_is_active(peer));
            let mut peers = peers.into_iter();
            if first_inactive == 0 {
                tracing::info!("No active clients");
            } else {
                println!("Active clients ({first_inactive}):");
                for (key, peer) in (&mut peers).take(first_inactive) {
                    let key = PublicKey::from(key);
                    if let Some(meta) = peers_meta.peer(&key) {
                        let display_data = PeerListData {
                            wg_peer: peer,
                            peer_meta: meta,
                        };
                        println!("{display_data}");
                    }
                }
                println!();
            }
            if peers.len() != 0 {
                println!("Inactive clients ({}):", peers.len());
                for (key, peer) in peers {
                    let key = PublicKey::from(key);
                    if let Some(meta) = peers_meta.peer(&key) {
                        let display_data = PeerListData {
                            wg_peer: peer,
                            peer_meta: meta,
                        };
                        println!("{display_data}");
                    }
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
                let output_path =
                    output.unwrap_or_else(|| Utf8PathBuf::from(format!("{}.conf", config.name)));
                output_file = std::fs::OpenOptions::new()
                    .mode(0o400)
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

            let new_peer = PeerMeta {
                comment: comment.clone(),
                name: name.clone(),
                ip,
                public_key,
            };

            let config_file_printer =
                wireguard_simple_manager::client_config::ConfigFilePrinter::builder()
                    .global_config(&config)
                    .client_name(&name)
                    .client_comment(comment.as_deref())
                    .client_secret_key(secret_key)
                    .preshared_key(Some(preshared_key.clone()))
                    .ip(ip)
                    .server_public_key(host_public_key)
                    .build();

            peers_meta
                .add_peer(new_peer)
                .whatever_context("Adding a new peer")?;

            let wg_peer = defguard_wireguard_rs::host::Peer {
                public_key: public_key.into(),
                preshared_key: Some(preshared_key.clone().into()),
                allowed_ips: vec![IpAddrMask::new(ip, 32)],
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

            if let Err(e) = write!(output, "{config_file_printer}") {
                let e = DisplayErrorChain::new(e);
                tracing::error!(
                    "Unable to write peer configuration file: {e}.\n\
                     Print file to stdout instead:\n"
                );
                println!("{config_file_printer}");
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

fn peer_is_active(peer: &defguard_wireguard_rs::host::Peer) -> bool {
    peer.last_handshake
        .map(|st| {
            const HALF_AN_HOUR: Duration = Duration::from_secs(30 * 60);
            st.elapsed()
                .map(|elapsed| elapsed < HALF_AN_HOUR)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

struct PeerListData<'a> {
    wg_peer: &'a defguard_wireguard_rs::host::Peer,
    peer_meta: &'a PeerMeta,
}

impl std::fmt::Display for PeerListData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const IDENT: &str = "┃  ";
        let key = &self.peer_meta.public_key;
        let name = &self.peer_meta.name;
        let ip = &self.peer_meta.ip;
        let last_handshake = self
            .wg_peer
            .last_handshake
            .and_then(|st| {
                if st == std::time::SystemTime::UNIX_EPOCH {
                    None
                } else {
                    Some(st)
                }
            })
            .map(time::OffsetDateTime::from);
        write!(
            f,
            "┏Client key: {key}\n\
             {IDENT}Name: {name}"
        )?;
        if let Some(comment) = &self.peer_meta.comment {
            write!(f, " ({comment})")?;
        }
        write!(
            f,
            "\n\
             {IDENT}Ip: {ip}"
        )?;
        if let Some(endpoint) = self.wg_peer.endpoint {
            write!(f, "\n{IDENT}Endpoint: {endpoint}")?;
        }
        if let Some(last_handshake) = last_handshake {
            let now = time::OffsetDateTime::now_utc();
            let elapsed = humantime::Duration::from(Duration::from_secs(
                (now - last_handshake).unsigned_abs().as_secs(),
            ));

            write!(
                f,
                "\n\
                 {IDENT}Last handshake: {elapsed} ago \
                 at {last_handshake}"
            )?;
        }

        Ok(())
    }
}
