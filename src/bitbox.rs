use crate::{DeviceKind, Error as HWIError, HWI};
use async_trait::async_trait;
use bitbox_api::{error::Error, runtime::TokioRuntime, PairedBitBox};
use bitcoin::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    psbt::Psbt,
};
use std::str::FromStr;

pub struct BitBox {
    pub network: bitcoin::Network,
    pub client: PairedBitBox<TokioRuntime>,
}

impl std::fmt::Debug for BitBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitBox").finish()
    }
}

impl BitBox {
    pub async fn connect() -> Result<Self, Error> {
        let noise_config = Box::new(bitbox_api::NoiseConfigNoCache {});
        let bitbox = bitbox_api::BitBox::<bitbox_api::runtime::TokioRuntime>::from(
            bitbox_api::usb::get_any_bitbox02().unwrap(),
            noise_config,
        )
        .await?;
        let pairing_bitbox = bitbox.unlock_and_pair().await?;
        Ok(BitBox {
            network: bitcoin::Network::Bitcoin,
            client: pairing_bitbox.wait_confirm().await?,
        })
    }

    pub fn with_network(mut self, network: bitcoin::Network) -> Self {
        self.network = network;
        self
    }
}

#[async_trait]
impl HWI for BitBox {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::BitBox
    }

    async fn get_version(&self) -> Result<super::Version, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn is_connected(&self) -> Result<(), HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        let fg = self
            .client
            .root_fingerprint()
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(fg)
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<ExtendedPubKey, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        Err(HWIError::UnimplementedMethod)
    }
}

impl From<BitBox> for Box<dyn HWI> {
    fn from(s: BitBox) -> Box<dyn HWI> {
        Box::new(s)
    }
}
