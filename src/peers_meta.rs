//! Peers meta information.

use std::{io::Write, net::IpAddr};

use camino::Utf8PathBuf;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

use crate::wg_key::PublicKey;

/// A single peer meta information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMeta {
    /// Public key.
    pub public_key: PublicKey,
    /// Full name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Peer's IP address.
    pub ip: IpAddr,
}

impl std::fmt::Display for PeerMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const IDENT: &str = "  ";
        write!(
            f,
            "public key: {}\n\
             {IDENT}name: {}\n\
             {IDENT}ip: {}\n",
            self.public_key, self.name, self.ip
        )?;
        if let Some(comment) = &self.comment {
            write!(f, "{IDENT}comment: {comment}")?;
        }
        Ok(())
    }
}

/// Meta information of peers stored as a dictionary.
#[derive(Debug, Clone)]
pub struct PeersMeta {
    inner: IndexMap<PublicKey, PeerMeta>,
    path: Utf8PathBuf,
}

impl std::fmt::Display for PeersMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for peer in self.peers() {
            write!(f, "{peer}")?;
        }
        Ok(())
    }
}

/// Load error.
#[derive(Debug, Snafu)]
pub enum LoadError {
    /// Unable to read the file.
    #[snafu(display("Unable to read the file"))]
    #[snafu(context(false))]
    ReadFile {
        /// Source error.
        source: std::io::Error,
    },
    /// Unable to deserialize the file.
    #[snafu(display("Unable to deserialize the file"))]
    #[snafu(context(false))]
    Deserialize {
        /// Source error.
        source: toml::de::Error,
    },
}

/// Save error.
#[derive(Debug, Snafu)]
pub enum SaveError {
    /// Unable to create a temporary file.
    #[snafu(display("Unable to create a temporary file in \"{parent}\""))]
    CreateTemp {
        /// Parent directory.
        parent: Utf8PathBuf,
        /// Source error.
        source: std::io::Error,
    },
    /// Unable to store the metadata to the temporary file.
    #[snafu(display("Unable to store the metadata to the temporary file"))]
    StoreToTemp {
        /// Source error.
        source: std::io::Error,
    },
    /// Unable to persist the temporary file.
    #[snafu(display("Unable to persist the temporary file"))]
    PersistTemp {
        /// Source error.
        source: std::io::Error,
    },
}

#[derive(Debug, Snafu)]
#[snafu(display("The peer already exists"))]
#[non_exhaustive]
pub struct PeerExists {}

impl PeersMeta {
    /// Loads peers metadata from the provided path.
    pub fn load<P>(path: P) -> Result<Self, LoadError>
    where
        P: Into<Utf8PathBuf>,
    {
        let path = path.into();
        let data = std::fs::read_to_string(&path)?;
        let inner: IndexMap<PublicKey, PeerMeta> = toml::from_str(&data)?;
        Ok(Self { inner, path })
    }

    /// Attempts to save the metadata in an atomic fashion.
    pub fn save(&self) -> Result<(), SaveError> {
        let parent = self.path.parent().expect("Must be a file");
        let mut tmp =
            tempfile::NamedTempFile::new_in(parent).context(CreateTempSnafu { parent })?;
        let serialized = toml::to_string_pretty(&self.inner).expect("Serialization must not fail");
        tmp.write_all(serialized.as_bytes())
            .context(StoreToTempSnafu)?;
        tmp.persist(&self.path)
            .map_err(|p| p.error)
            .context(PersistTempSnafu)?;
        Ok(())
    }

    /// Finds out a peer meta information by the peer's public key.
    pub fn peer(&self, key: &PublicKey) -> Option<&PeerMeta> {
        self.inner.get(key)
    }

    /// Adds a peer meta.
    ///
    /// Returns an error if there is a peer with the provided public key.
    pub fn add_peer(&mut self, meta: PeerMeta) -> Result<(), PeerExists> {
        match self.inner.entry(meta.public_key) {
            indexmap::map::Entry::Occupied(_) => PeerExistsSnafu.fail(),
            indexmap::map::Entry::Vacant(vacant) => {
                vacant.insert(meta);
                Ok(())
            }
        }
    }

    /// Removes the peer by its public key.
    ///
    /// If there is no such a peer, the method returns [`None`], the meta
    /// information is returned.
    pub fn remove_peer(&mut self, key: &PublicKey) -> Option<PeerMeta> {
        self.inner.shift_remove(key)
    }

    /// Returns an iterator over the stored peers.
    pub fn peers(&self) -> impl Iterator<Item = &PeerMeta> + '_ {
        self.inner.values()
    }

    /// Calculates the maximum assigned IP address.
    pub fn last_ip(&self) -> Option<IpAddr> {
        self.inner.values().map(|peer| peer.ip).max()
    }

    /// Finds a peer by IP address.
    pub fn peer_by_ip(&self, ip: IpAddr) -> Option<&PeerMeta> {
        self.inner.values().find(|peer| peer.ip == ip)
    }
}
