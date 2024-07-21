//! A wireguard key wrapper.

use std::str::FromStr;

use base64::Engine;
use curve25519_dalek::EdwardsPoint;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct PrivateKey(Key);

impl From<defguard_wireguard_rs::key::Key> for PrivateKey {
    fn from(value: defguard_wireguard_rs::key::Key) -> Self {
        Self(Key(value.as_array()))
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl PrivateKey {
    /// Generates a random private key.
    pub fn random<R: rand::CryptoRng + rand::Rng + ?Sized>(r: &mut R) -> Self {
        let mut buf = [0u8; 32];
        r.fill_bytes(&mut buf);
        Self(Key(buf))
    }

    /// Calculates the [`PublicKey`] which corresponds to the current private
    /// key.
    pub fn public(&self) -> PublicKey {
        let public_bytes = EdwardsPoint::mul_base_clamped(self.0 .0)
            .to_montgomery()
            .to_bytes();
        PublicKey(Key(public_bytes))
    }
}

impl FromStr for PrivateKey {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

/// Preshared wireguard key.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PresharedKey(Key);

impl PresharedKey {
    /// Generates a random preshared key.
    pub fn random<R: rand::CryptoRng + rand::Rng + ?Sized>(r: &mut R) -> Self {
        let mut buf = [0u8; 32];
        r.fill_bytes(&mut buf);
        Self(Key(buf))
    }
}

impl From<PresharedKey> for defguard_wireguard_rs::key::Key {
    fn from(value: PresharedKey) -> Self {
        defguard_wireguard_rs::key::Key::new(value.0 .0)
    }
}

impl std::fmt::Display for PresharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct PublicKey(Key);

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for PublicKey {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl From<&'_ defguard_wireguard_rs::key::Key> for PublicKey {
    fn from(value: &'_ defguard_wireguard_rs::key::Key) -> Self {
        Self(Key(value.as_array()))
    }
}

impl From<PublicKey> for defguard_wireguard_rs::key::Key {
    fn from(value: PublicKey) -> Self {
        defguard_wireguard_rs::key::Key::new(value.0 .0)
    }
}

/// Parse key error.
#[derive(Debug, Snafu)]
pub enum ParseKeyError {
    /// Base64 decoding error.
    #[snafu(display("Base64 decoding error"))]
    #[snafu(context(false))]
    Base64Decoding {
        /// Source error.
        source: base64::DecodeSliceError,
    },
    /// The decoded key is of a wrong size.
    #[snafu(display("The decoded key must be 32 bytes long, but fot {got} bytes"))]
    WrongLength {
        /// The amount of bytes in the decoded data.
        got: usize,
    },
}

impl FromStr for Key {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut buf = [0u8; 32];
        let decoded_bytes = base64::engine::general_purpose::STANDARD.decode_slice(s, &mut buf)?;
        snafu::ensure!(decoded_bytes == 32, WrongLengthSnafu { got: decoded_bytes });
        Ok(Self(buf))
    }
}

/// A generic wireguard 32-bytes long key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
struct Key([u8; 32]);

impl serde::Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(self.0.as_slice());
        encoded.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        encoded
            .parse()
            .map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = base64::engine::general_purpose::STANDARD.encode(self.0.as_slice());
        std::fmt::Display::fmt(&encoded, f)
    }
}
