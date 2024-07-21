//! Configuration file utils.

use camino::Utf8PathBuf;
use defguard_wireguard_rs::net::IpAddrMask;

/// Main configuration file.
#[derive(Debug, serde::Deserialize)]
pub struct Config {
    /// Name of the network.
    pub name: String,

    /// External VPN IP or DNS address.
    pub external_address: String,

    /// External VPN port.
    pub external_port: u32,

    /// Path to the peers meta information.
    pub peers: Utf8PathBuf,

    /// Name of the wireguard interface.
    #[serde(rename = "interface")]
    pub interface_name: String,

    /// VPN network mask.
    #[serde(with = "serde_ip_addr_mask")]
    pub network_mask: IpAddrMask,
}

mod serde_ip_addr_mask {
    use defguard_wireguard_rs::net::IpAddrMask;
    // use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
    use serde::{de::Error as _, Deserialize, Deserializer};
    use snafu::{OptionExt, ResultExt, Snafu};

    /// Deserializes an ip address with a mask.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<IpAddrMask, D::Error>
    where
        D: Deserializer<'de>,
    {
        let stringified = String::deserialize(deserializer)?;
        parse_ip_mask(&stringified)
            .map_err(|e| format!("Parse {stringified:?}: {e}"))
            .map_err(D::Error::custom)
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
}
