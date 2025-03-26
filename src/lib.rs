use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];
pub const SECRET_KEY_LENGTH: usize = 64;
pub type SecretKey = [u8; SECRET_KEY_LENGTH];

/// Formats the sum of two numbers as string.
#[pyfunction]
fn shared_secret(secret_key: SecretKey, their_public: PublicKey) -> PyResult<[u8; 32]> {
    let comressed_ristreretto = CompressedRistretto::from_slice(their_public.as_ref())
        .map_err(|_| PyValueError::new_err("Invalid public key"))?;
    let uncompressed_ristretto = comressed_ristreretto
        .decompress()
        .ok_or_else(|| PyValueError::new_err("Invalid public key"))?;

    let secret = uncompressed_ristretto
        * Scalar::from_bytes_mod_order(
            secret_key[..32]
                .try_into()
                .map_err(|_| PyValueError::new_err("Invalid secret key"))?,
        );

    Ok(secret.compress().to_bytes())
}

/// A Python module implemented in Rust.
#[pymodule]
fn sr25519_ecdh(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(shared_secret, m)?)?;
    Ok(())
}
