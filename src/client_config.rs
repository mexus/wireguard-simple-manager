//! Clients config file generation.

use std::net::IpAddr;

use typed_builder::TypedBuilder;

use crate::wg_key::{PresharedKey, PrivateKey, PublicKey};

/// A helper to display a wg-quick compatible configuration file for a peer.
#[derive(TypedBuilder, Clone)]
pub struct ConfigFilePrinter<'a> {
    global_config: &'a crate::config::Config,
    listen_port: u16,
    endpoint_name: &'a str,
    client_name: &'a str,
    client_comment: Option<&'a str>,
    ip: IpAddr,
    server_public_key: PublicKey,
    preshared_key: Option<PresharedKey>,
    client_secret_key: PrivateKey,
}

impl<'a> std::fmt::Display for ConfigFilePrinter<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vpn_name = &self.global_config.name;
        let dns = self.global_config.dns.as_deref();
        let network_mask = &self.global_config.network_mask;
        let endpoint_name = self.endpoint_name;
        let endpoint_port = self.global_config.external_port.unwrap_or(self.listen_port);

        let ConfigFilePrinter {
            client_name,
            client_comment,
            ip,
            server_public_key,
            preshared_key,
            client_secret_key,
            ..
        } = self;

        writeln!(
            f,
            "# VPN: \"{vpn_name}\"
# Peer name: \"{client_name}\""
        )?;
        for comment in client_comment.unwrap_or_default().lines() {
            let comment = comment.trim();
            writeln!(f, "# Comment: {comment}")?;
        }

        // Mask for a single IP address.
        let ip_mask = if ip.is_ipv4() { 32 } else { 128 };

        writeln!(
            f,
            "[Interface]\n\
             Address = {ip}/{ip_mask}\n\
             PrivateKey = {client_secret_key}"
        )?;

        if let Some(dns) = dns {
            writeln!(f, "DNS = {dns}")?;
        }

        writeln!(
            f,
            "[Peer]\n\
             PublicKey = {server_public_key}\n\
             AllowedIPs = {network_mask}\n\
             Endpoint = {endpoint_name}:{endpoint_port}\n\
             PersistentKeepalive = 25"
        )?;

        if let Some(preshared_key) = preshared_key {
            writeln!(f, "PresharedKey = {preshared_key}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_config() {
        let private_key = PrivateKey::random(&mut rand::rngs::OsRng);
        let preshared_key = PresharedKey::random(&mut rand::rngs::OsRng);
        let server_public_key = PublicKey::random(&mut rand::rngs::OsRng);

        let network_config = crate::config::Config {
            name: "VPN human-readable name".into(),
            external_address: None,
            external_port: Some(54321),
            peers: "/path/to/the/peers".into(),
            dns: Some("192.168.0.1".into()),
            interface_name: "wg0".into(),
            network_mask: defguard_wireguard_rs::net::IpAddrMask {
                ip: "192.168.0.0".parse().unwrap(),
                cidr: 24,
            },
        };
        let printer = ConfigFilePrinter::builder()
            .global_config(&network_config)
            .client_name("Client name")
            .client_comment(Some("Multiline\ncomment"))
            .client_secret_key(private_key.clone())
            .preshared_key(Some(preshared_key.clone()))
            .ip("192.168.0.115".parse().unwrap())
            .server_public_key(server_public_key)
            .listen_port(1)
            .endpoint_name("vpn.example.com")
            .build();
        assert_eq!(
            printer.to_string(),
            format!(
                "\
# VPN: \"VPN human-readable name\"
# Peer name: \"Client name\"
# Comment: Multiline
# Comment: comment
[Interface]
Address = 192.168.0.115/32
PrivateKey = {private_key}
DNS = 192.168.0.1
[Peer]
PublicKey = {server_public_key}
AllowedIPs = 192.168.0.0/24
Endpoint = vpn.example.com:54321
PersistentKeepalive = 25
PresharedKey = {preshared_key}
"
            )
        );
    }
}
