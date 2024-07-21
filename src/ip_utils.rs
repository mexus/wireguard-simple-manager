//! IP address utilities.

use std::net::IpAddr;

use defguard_wireguard_rs::net::IpAddrMask;
use snafu::{OptionExt, Snafu};

/// Checks whether IP belongs to a mask.
pub fn check_ip(ip: IpAddr, mask: &IpAddrMask) -> bool {
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

/// Addresses in the network are exhausted.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(display("Network exhausted"))]
pub struct SubNetworkExhausted {}

/// Calculates the next IP in the sub network.
pub fn next_ip(last_ip: IpAddr, mask: &IpAddrMask) -> Result<IpAddr, SubNetworkExhausted> {
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

#[cfg(test)]
mod test {
    use super::*;

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
}
