use crate::{DeviceKind, Error as HWIError, HWI};
use async_trait::async_trait;
use bitbox_api::{
    btc::KeyOriginInfo,
    error::Error,
    pb::{self, BtcScriptConfig},
    runtime::TokioRuntime,
    Keypath, PairedBitBox,
};
use bitcoin::{
    bip32::{DerivationPath, ExtendedPubKey, Fingerprint},
    psbt::Psbt,
};
use regex::Regex;
use std::str::FromStr;

pub struct BitBox {
    pub network: bitcoin::Network,
    pub display_xpub: bool,
    pub client: PairedBitBox<TokioRuntime, bitbox_api::usb::Transport>,
}

impl std::fmt::Debug for BitBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitBox").finish()
    }
}

impl BitBox {
    pub async fn connect() -> Result<Self, Error> {
        let noise_config = Box::new(bitbox_api::NoiseConfigNoCache {});
        let bitbox = bitbox_api::BitBox::<
            bitbox_api::runtime::TokioRuntime,
            bitbox_api::usb::Transport,
        >::from(bitbox_api::usb::get_any_bitbox02().unwrap(), noise_config)
        .await?;
        let pairing_bitbox = bitbox.unlock_and_pair().await?;
        Ok(BitBox {
            display_xpub: false,
            network: bitcoin::Network::Bitcoin,
            client: pairing_bitbox.wait_confirm().await?,
        })
    }

    pub fn with_network(mut self, network: bitcoin::Network) -> Self {
        self.network = network;
        self
    }

    pub fn display_xpub(mut self, value: bool) -> Self {
        self.display_xpub = value;
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
        Ok(Fingerprint::from_str(&fg).map_err(|e| HWIError::Device(e.to_string()))?)
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<ExtendedPubKey, HWIError> {
        let fg = self
            .client
            .btc_xpub(
                if self.network == bitcoin::Network::Bitcoin {
                    pb::BtcCoin::Btc
                } else {
                    pb::BtcCoin::Tbtc
                },
                &Keypath::from(path),
                pb::btc_pub_request::XPubType::Xpub,
                self.display_xpub,
            )
            .await
            .map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(ExtendedPubKey::from_str(&fg).map_err(|e| HWIError::Device(e.to_string()))?)
    }

    async fn register_wallet(
        &self,
        name: &str,
        policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        let policy = extract_script_config_policy(&policy)?;
        self.client
            .btc_register_script_config(
                if self.network == bitcoin::Network::Bitcoin {
                    pb::BtcCoin::Btc
                } else {
                    pb::BtcCoin::Tbtc
                },
                &policy,
                &keypath_account,
                pb::btc_register_script_config_request::XPubType::AutoXpubTpub,
                Some(name),
            )
            .await
            .unwrap();
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

pub fn extract_script_config_policy(policy: &str) -> Result<BtcScriptConfig, HWIError> {
    let re = Regex::new(r"((\[.+?\])?[xyYzZtuUvV]pub[1-9A-HJ-NP-Za-km-z]{79,108})").unwrap();
    let mut descriptor_template = policy.to_string();
    let mut pubkeys: Vec<KeyOriginInfo> = Vec::new();
    for (index, capture) in re.find_iter(policy).enumerate() {
        let capture = capture.as_str();
        let pubkey = if let Ok(key) = ExtendedPubKey::from_str(capture) {
            KeyOriginInfo {
                keypath: None,
                root_fingerprint: None,
                xpub: key,
            }
        } else {
            let (keysource_str, xpub_str) = capture
                .strip_prefix('[')
                .and_then(|s| s.rsplit_once(']'))
                .ok_or(HWIError::InvalidParameter(
                    "policy",
                    "Invalid key source".to_string(),
                ))?;
            let (f_str, path_str) = keysource_str.split_once('/').unwrap_or((keysource_str, ""));
            let fingerprint = Fingerprint::from_str(f_str)
                .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?;
            let derivation_path = if path_str.is_empty() {
                DerivationPath::master()
            } else {
                DerivationPath::from_str(&format!("m/{}", path_str))
                    .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?
            };
            let (xpub_str, multipath) = if let Some((xpub, multipath)) = xpub_str.rsplit_once('/') {
                (xpub, Some(format!("/{}", multipath)))
            } else {
                (xpub_str, None)
            };
            KeyOriginInfo {
                xpub: ExtendedPubKey::from_str(xpub_str)
                    .map_err(|e| HWIError::InvalidParameter("policy", e.to_string()))?,
                keypath: Some(Keypath::from(&derivation_path)),
                root_fingerprint: Some(fingerprint),
            }
        };
        if !pubkeys.contains(&pubkey) {
            pubkeys.push(pubkey);
        }
        descriptor_template = descriptor_template.replace(capture, &format!("@{}", index));
    }

    // Do not include the hash in the descriptor template.
    let template = if let Some((descriptor_template, _hash)) = descriptor_template.rsplit_once('#')
    {
        descriptor_template
    } else {
        &descriptor_template
    };

    Ok(bitbox_api::btc::make_script_config_policy(
        template, &pubkeys,
    ))
}
