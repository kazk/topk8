//! Convert private keys to PKCS#8 format in pure Rust.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use thiserror::Error;

/// Errors from [`from_sec1_pem`]
#[derive(Debug, Error)]
pub enum ConvertSec1Error {
    /// Failed to deserialize SEC1 private key from PEM
    #[error("failed to deserialize SEC1 private key from PEM")]
    Deserialize(#[source] sec1::Error),

    /// Failed to serialize private key to PKCS#8 PEM
    #[error("failed to serialize private key to PKCS#8 PEM")]
    Serialize(#[source] sec1::pkcs8::Error),
}

/// Convert a private key from SEC1 PEM (`EC PRIVATE KEY` ) to PKCS#8 PEM (`PRIVATE KEY`).
///
/// # Errors
///
/// Returns `Err` when de/serialization fails. See [`ConvertSec1Error`].
pub fn from_sec1_pem(pem: &str) -> Result<String, ConvertSec1Error> {
    use sec1::{
        pkcs8::{EncodePrivateKey, LineEnding, PrivateKeyDocument},
        DecodeEcPrivateKey,
    };
    let pkdoc = PrivateKeyDocument::from_sec1_pem(pem).map_err(ConvertSec1Error::Deserialize)?;
    let pkcs8_pem = pkdoc
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(ConvertSec1Error::Serialize)?;
    let pkcs8_pem: &str = pkcs8_pem.as_ref();
    Ok(pkcs8_pem.to_owned())
}

/// Errors from [`from_pkcs1_pem`]
#[derive(Debug, Error)]
pub enum ConvertPkcs1Error {
    /// Failed to deserialize PKCS#1 private key from PEM
    #[error("failed to deserialize PKCS#1 private key from PEM")]
    Deserialize(#[source] rsa::pkcs1::Error),

    /// Failed to serialize private key to PKCS#8 PEM
    #[error("failed to serialize private key to PKCS#8 PEM")]
    Serialize(#[source] rsa::pkcs8::Error),
}

/// Convert a private key from PKCS#1 PEM (`RSA PRIVATE KEY` ) to PKCS#8 PEM (`PRIVATE KEY`).
///
/// # Errors
///
/// Returns `Err` when de/serialization fails. See [`ConvertPkcs1Error`].
pub fn from_pkcs1_pem(pem: &str) -> Result<String, ConvertPkcs1Error> {
    use rsa::{pkcs1::FromRsaPrivateKey, pkcs8::ToPrivateKey, RsaPrivateKey};
    let pkey = RsaPrivateKey::from_pkcs1_pem(pem).map_err(ConvertPkcs1Error::Deserialize)?;
    let pkcs8_pem = pkey.to_pkcs8_pem().map_err(ConvertPkcs1Error::Serialize)?;
    let pkcs8_pem: &str = pkcs8_pem.as_ref();
    Ok(pkcs8_pem.to_owned())
}

// TODO Test against OpenSSL
#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_rsa_conv() {
        let rsa_pem = indoc! {"
            -----BEGIN RSA PRIVATE KEY-----
            MIIEogIBAAKCAQEAq4hCIPSe4ic/g2v2CfdwwvWywxtQDu47kcD47AJyOm0Ancdz
            VfsNeji76Cl8DjOGMAEPsftVqDI8NgrgeUGG/qEsClxGgdb+6RUb4aU3/iPMDmwM
            /rb6iF5lLCp1vafGxjDB6FcBksv5JvXjX1vgVoLSsCBzBHrqiSPx3NkA9ryCexES
            8AklvxeYMI4qBoMpDwk0mWpSerknzQLg3XpMl7fMJI03Kc5iQ0pPOLGE5kW4j0bg
            bFi9dbkLiSqbF/JlvnpgqXRiEkp+zt3ItiaqH9Xk47QsAJEyZSJmoLUaPGU7Dw/d
            9m+HbIIPzTYslukbYZ+cEIWGgAkR8gjzYoUM7wIDAQABAoIBAGOsX9DKlHCRoeR6
            HZQZBpsjLmcVPeYPJOpDGeH6Yen1YQBN34U8xs4YnYgAYyfVZMoMM9SWWWXNGxPE
            KkALhaf8e5zhlc7o4WMLcxIhcXHp1y8iNkLkjJwlTeDmI1i7X1PXDTY3KKDmibbL
            9v14Y9mhV1Ak6vDVg+eAzZApQNgeKdHALeAzcHONsGTzTudwx6bz5eQUrFuYv+lP
            Ig5RkJmR5aLOaOVMjnWbze0r2zp3awOdKZZqdK0V0+VYwImAR5HdUGGkk4Pte8PW
            cOBNiAr8FGunOZTKvDb7zfSxysD9OFX0BGHqjnJnH0MtIGfbPvFN7dYPzRpOGQjf
            AmYRcZECgYEA420kdlruO8koDKnX35qmOO16z/O2iOiiDMJf24xJhJUOkQrZXgvd
            31qDJM3wOEoeThqy1/O9pBWf57J1xoZ9OowL+JgwfBH3DUmilbvj6Hsm9//Tozd+
            KUh6Jenpev+wxsCsieyYTWVTF6TkLPlr02zOUVir2qRWjErsuAsxe8MCgYEAwRVb
            8xHIPP0BtYlZZwbNM01t4NX6cxstmhRxw4XJ5YAYtLrIaDJ1sicbEEYljbGG0p4l
            4uH1QHLdE3f4idq9NidHmoFjKbf8pY5OFYdcH8r5EDKZGC+rJE/5tS6P7m83eikC
            arTkFz2AuonfSpbq0qlK/7JryyuM9kyWRiS1U2UCgYBFuusZFtxAnHaZG2JC/unE
            PpwPMoxfAeTdwKMfb64C5qjms8rd2QmYN+pJ2JK0z5TnIayAJg2ZR8AVjFQsIIQ4
            9UOeXxtOjzuOaWteOZOxbkEOfPPo8VTPV5eMFGIwAkGzTtQYHeC8qjqF31rOp1L2
            KkBAFM3sZcLblQVrkJMFfQKBgGMozf0J/9Tadps9e21+v7l+JVTXb3TX21aK81Xf
            iq1TWNzQJAXnDCy/CpYUAEtBhaT61SgstSAxHTpXXYumi4+ZIpvFoSCWvahkadOC
            nZwySDC6W4dhS7otXGdhD0f7U/lnwDb+yTjqPAcQsV0EHnqruLmSbut7ZTxEXtSN
            G5ZFAoGAdqdMpTyXjYf/+offQm7YMCgx96cJZRZzly82dH16/EQwtqJ1CFWpdJbv
            7zON6qU4tgiHAE4vr8V5WZBPmr1K3akXqiQG9H6prZPnbSS1fT5CQxXyrPVrQ45B
            S3EEkoilj5aqRWN+AfTHXikd0Bl6X+gXZbHQ6gdp8QkeeRzI6Xg=
            -----END RSA PRIVATE KEY-----
        "};
        // println!("{}", rsa_pem);
        // println!("{}", pkcs1_pem(rsa_pem).unwrap());
        let pkcs8_pem = from_pkcs1_pem(rsa_pem).unwrap();
        assert!(pkcs8_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pkcs8_pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn test_ec_conv() {
        let ec_pem = indoc! {"
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIAL4r6d9lPq3XEDSZTL9l0D6thrPM7RiAhl3Fjuw9Ji2oAoGCCqGSM49
            AwEHoUQDQgAE4U64dviQRMujGK0g80dwzgjV7fnwLkj6RfvINMHvD6eiCsphWIlq
            cddTAoOjXVQDu3qMAS1Ghfyk1F377EW1Sw==
            -----END EC PRIVATE KEY-----
        "};
        // println!("{}", ec_pem);
        // println!("{}", sec1_pem(ec_pem).unwrap());
        let pkcs8_pem = from_sec1_pem(ec_pem).unwrap();
        assert!(pkcs8_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pkcs8_pem.ends_with("-----END PRIVATE KEY-----\n"));
    }
}
