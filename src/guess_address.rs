//! A module to guess the external address.

use std::time::Duration;

use snafu::{ResultExt, Snafu};

/// Tries to guess the host's external IP address by sending a request to the
/// `ifconfig.me`.
pub fn guess_ip_address() -> Result<std::net::IpAddr, GuessError> {
    // let x = reqwest::get("http://ifconfig.me/").await.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context(SetupTokioRuntimeSnafu)?;
    let _guard = rt.enter();
    rt.block_on(guess_ip_address_impl())
}

async fn guess_ip_address_impl() -> Result<std::net::IpAddr, GuessError> {
    const TIMEOUT: Duration = Duration::from_secs(5);

    let download = async {
        let response = reqwest::get("http://ifconfig.me")
            .await
            .context(SendRequestSnafu)?;
        snafu::ensure!(
            response.status().is_success(),
            UnsuccessResponseSnafu {
                status: response.status()
            }
        );
        response.bytes().await.context(DownloadResponseSnafu)
    };
    let response = tokio::time::timeout(TIMEOUT, download).await??;
    let address = std::str::from_utf8(&response)?;
    address.parse().context(InvalidAddressSnafu { address })
}

/// An error happened while guessing the address.
#[derive(Debug, Snafu)]
pub enum GuessError {
    /// Unable to build a Tokio runtime.
    #[snafu(display("Unable to build a Tokio runtime"))]
    SetupTokioRuntime {
        /// Source error.
        source: std::io::Error,
    },
    /// Unable to send a request.
    #[snafu(display("Unable to send a request"))]
    SendRequest {
        /// Source error.
        source: reqwest::Error,
    },
    /// Received a non-success response.
    #[snafu(display("Received a non-success response {status}"))]
    UnsuccessResponse {
        /// The status code.
        status: reqwest::StatusCode,
    },
    /// Can't download response.
    #[snafu(display("Can't download response"))]
    DownloadResponse {
        /// Source error.
        source: reqwest::Error,
    },
    /// Received a non-utf8 response.
    #[snafu(display("Received a non-utf8 response"))]
    #[snafu(context(false))]
    NonUtf8Response {
        /// Source error.
        source: std::str::Utf8Error,
    },
    /// Unable to parse the returned address.
    #[snafu(display("Unable to parse the returned address {address:?}"))]
    InvalidAddress {
        /// The returned address.
        address: String,
        /// Parse error.
        source: std::net::AddrParseError,
    },
    /// Time out elapsed.
    #[snafu(display("Time out elapsed"))]
    #[snafu(context(false))]
    TimedOut {
        /// Source error.
        source: tokio::time::error::Elapsed,
    },
}
