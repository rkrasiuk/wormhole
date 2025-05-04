use crate::{constants::MAGIC_NULLIFIER, MAGIC_ADDRESS, MAGIC_POW, POW_DIFFICULTY_U256};
use alloy_primitives::{bytes::BytesMut, Address, Bytes, B256, U256};
use core::ops::Rem;
use derive_more::AsRef;

/// The secret preimage for burn address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, AsRef)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WormholeSecret(Bytes);

impl TryFrom<Bytes> for WormholeSecret {
    type Error = Self;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        let secret = Self::new_unchecked(value);
        if secret.is_valid() {
            Ok(secret)
        } else {
            Err(secret)
        }
    }
}

impl WormholeSecret {
    /// Create new [`WormholeSecret`] from bytes.
    /// NOTE: No secret validation is performed in this method.
    pub fn new_unchecked(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// Creates new **valid** [`WormholeSecret`] with cryptographically random content.
    ///
    /// # Panics
    ///
    /// Panics if the underlying call to
    /// [`getrandom_uninit`](getrandom::getrandom_uninit) fails.
    #[inline]
    pub fn random() -> Self {
        Self::try_random().unwrap()
    }

    /// Tries to mine for a new **valid** [`WormholeSecret`] with cryptographically random content.
    ///
    /// # Errors
    ///
    /// This function only propagates the error from the underlying call to
    /// [`getrandom_uninit`](getrandom::getrandom_uninit).
    #[inline]
    pub fn try_random() -> Result<Self, getrandom::Error> {
        let mut bytes = BytesMut::zeroed(32); // TODO: reconsider or justify secret length
        loop {
            getrandom::getrandom(&mut bytes)?;
            if is_valid_wormhole_secret(&bytes) {
                return Ok(Self(bytes.freeze().into()));
            }
        }
    }

    /// Returns `true` if the secret is valid.
    pub fn is_valid(&self) -> bool {
        is_valid_wormhole_secret(&self.0)
    }

    /// Returns Proof-of-Work hash for this secret.
    /// `sha256(MAGIC_POW + secret)`
    pub fn proof_of_work_hash(&self) -> B256 {
        proof_of_work_secret_hash(&self.0)
    }

    /// Returns the burn address for this secret.
    /// `sha256(MAGIC_ADDRESS + secret)[12:]`
    pub fn burn_address(&self) -> Address {
        let address_hash = sha256([&[MAGIC_ADDRESS], self.0.as_ref()].concat());
        Address::from_slice(&address_hash[12..])
    }

    /// Returns the nullifier hash for this secret and provided index.
    /// `sha256(MAGIC_NULLIFIER + secret + index)`
    pub fn nullifier(&self, index: U256) -> B256 {
        sha256([&[MAGIC_NULLIFIER], self.0.as_ref(), index.as_le_slice()].concat())
    }
}

/// Returns Proof-of-Work hash for provided secret.
/// `sha256(MAGIC_POW + secret)`
#[inline]
pub fn proof_of_work_secret_hash(secret: impl AsRef<[u8]>) -> B256 {
    sha256([&[MAGIC_POW], secret.as_ref()].concat())
}

/// Returns `true` if the provided Wormhole secret is valid.
/// `sha256(MAGIC_POW + secret) % 2**POW_LOG_DIFFICULTY == 0`
#[inline]
pub fn is_valid_wormhole_secret(secret: impl AsRef<[u8]>) -> bool {
    let pow_hash = proof_of_work_secret_hash(secret);
    U256::from_be_bytes(*pow_hash).rem(POW_DIFFICULTY_U256).is_zero()
}

#[inline]
fn sha256(data: impl AsRef<[u8]>) -> B256 {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(data);
    B256::new(hash.finalize().into())
}

/// A valid Wormhole secret that can be used for testing.
#[cfg(any(test, feature = "test-utils"))]
pub const TEST_SECRET: WormholeSecret =
    WormholeSecret(Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x5d, 0xc6]));

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::bytes::{BufMut, BytesMut};

    #[test]
    fn test_secret_is_valid() {
        assert!(TEST_SECRET.is_valid());
    }

    #[cfg(feature = "std")]
    #[test]
    fn find_valid_secret() {
        let started_at = std::time::Instant::now();
        for i in 0..u64::MAX {
            let mut bytes = BytesMut::new();
            bytes.put_u64(i);

            let secret = bytes.freeze();
            if is_valid_wormhole_secret(&secret) {
                println!("found secret {i} in {:?}", started_at.elapsed());
                println!("secret {:?}", alloy_primitives::hex::encode(&secret[..]));
                break;
            }
        }
    }
}
