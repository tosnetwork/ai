#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    io::{self, Read},
    sync::RwLock,
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use tls_codec::{DeserializeBytes, Serialize as TlsSerialize};

const SCHEMA: &str = "tos.openmls.sidecar.v1";
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_REQUEST: u64 = 4 * 1024 * 1024;
const MAX_STATE: usize = 512 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_KEY: usize = 64 * 1024;
const MAX_VALUE: usize = 512 * 1024;
const MAX_IDENTITY: usize = 4096;
const MAX_MESSAGE: usize = 1024 * 1024;
// MAX_AAD bounds a message's authenticated data, sealed or opened.
const MAX_AAD: usize = 64 * 1024;
// Application messages sealed just before a Commit arrive after it, because
// the authority's fan-out takes minutes. Two past epochs cover that window at
// little forward-secrecy cost; anything older is reported as a gap.
const MAX_PAST_EPOCHS: usize = 2;
// The out-of-order tolerance is how many skipped generations each sender
// ratchet keeps, in the current and each retained epoch; a message further
// behind is a gap. It is what bounds the state: 31 other members x 8 keys x
// 3 epochs stays well inside MAX_STATE at the relay room bound of 32 leaves.
const OUT_OF_ORDER_TOLERANCE: u32 = 8;
// The forward distance is how far ahead of a sender's ratchet a message may
// be. Jumping ahead derives every skipped secret but keeps only the last
// OUT_OF_ORDER_TOLERANCE of them, so it does not change the state bound; it
// bounds the work one message can cost a receiver (1,000 ratchet steps).
const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;
// The most leaves a group may hold: the profile's bound (several devices per
// Agent). The relay room bound is 32.
const MAX_LEAVES: usize = 64;

fn sender_ratchet() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAXIMUM_FORWARD_DISTANCE)
}

#[derive(Default)]
struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    identity: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    group_id: String,
    #[serde(default)]
    key_package: String,
    #[serde(default)]
    key_packages: Vec<String>,
    #[serde(default)]
    remove_identities: Vec<String>,
    #[serde(default)]
    welcome: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    aad: String,
    #[serde(default)]
    plaintext: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    context: String,
    #[serde(default)]
    length: u16,
}

#[derive(Default, Serialize)]
struct Response {
    schema: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    public_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    key_package: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    commit: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    welcome: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    plaintext: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    group_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    secret: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    sender_identity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    epoch_authenticator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch: Option<u64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    sender_signature_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_leaf_index: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    members: Vec<MemberOut>,
    // aad is the authenticated data of a message `open_readback` opened; no
    // other operation sets it.
    #[serde(skip_serializing_if = "String::is_empty")]
    aad: String,
}

// AadMode is how opening treats a PrivateMessage's authenticated data.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AadMode {
    // Compare (`open`): the caller passes the exact authenticated data (an
    // absent field is the empty value) and a message carrying any other is
    // refused.
    Compare,
    // Readback (`open_readback`, never chosen by an absent field): the caller
    // passes none, and the message's own authenticated data is returned once
    // the message opened, for the caller to judge.
    Readback,
}

// MemberOut is one leaf of the current ratchet tree as `members` reports it.
#[derive(Serialize)]
struct MemberOut {
    index: u32,
    identity: String,
    signature_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    signer_public: String,
    #[serde(default)]
    group_id: String,
    entries: Vec<Entry>,
    // The leaf signature keys of the retained past epochs, newest last. The
    // library keeps those epochs' trees but does not expose their keys, and a
    // message opened in a past epoch must report the key of the leaf that
    // sealed it in that epoch.
    #[serde(default)]
    past_leaves: Vec<EpochLeaves>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct EpochLeaves {
    epoch: u64,
    leaves: Vec<LeafKey>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LeafKey {
    index: u32,
    key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    key: String,
    value: String,
}

fn decode(label: &str, value: &str, max: usize) -> Result<Vec<u8>, String> {
    let bytes = B64
        .decode(value)
        .map_err(|_| format!("invalid {label} encoding"))?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(format!("invalid {label} length"));
    }
    Ok(bytes)
}

fn encode<T: TlsSerialize>(value: &T) -> Result<String, String> {
    value
        .tls_serialize_detached()
        .map(|v| B64.encode(v))
        .map_err(|_| "MLS serialization failed".into())
}

fn decode_tls<T: DeserializeBytes>(label: &str, value: &str, max: usize) -> Result<T, String> {
    let bytes = decode(label, value, max)?;
    let (parsed, rest) =
        T::tls_deserialize_bytes(&bytes).map_err(|_| format!("invalid {label}"))?;
    if !rest.is_empty() {
        return Err(format!("trailing {label} bytes"));
    }
    Ok(parsed)
}

fn load_snapshot(encoded: &str) -> Result<(Provider, Snapshot), String> {
    let raw = decode("state", encoded, MAX_STATE)?;
    let snapshot: Snapshot =
        serde_json::from_slice(&raw).map_err(|_| "invalid state snapshot".to_string())?;
    if snapshot.schema != SCHEMA || snapshot.entries.len() > MAX_ENTRIES {
        return Err("unsupported state snapshot".into());
    }
    if snapshot.past_leaves.len() > MAX_PAST_EPOCHS {
        return Err("invalid past epoch leaves".into());
    }
    for (position, epoch) in snapshot.past_leaves.iter().enumerate() {
        if epoch.leaves.is_empty() || epoch.leaves.len() > MAX_LEAVES {
            return Err("invalid past epoch leaves".into());
        }
        if position > 0 && epoch.epoch <= snapshot.past_leaves[position - 1].epoch {
            return Err("past epoch leaves out of order".into());
        }
        for (index, leaf) in epoch.leaves.iter().enumerate() {
            if index > 0 && leaf.index <= epoch.leaves[index - 1].index {
                return Err("past epoch leaves out of order".into());
            }
            if decode("past leaf key", &leaf.key, 64)?.len() != 32 {
                return Err("invalid past leaf key".into());
            }
        }
    }
    let signer = decode("signer public key", &snapshot.signer_public, 64)?;
    if signer.len() != 32 {
        return Err("invalid signer public key".into());
    }
    let mut values = HashMap::with_capacity(snapshot.entries.len());
    let mut total = 0usize;
    for entry in &snapshot.entries {
        let key = decode("state key", &entry.key, MAX_KEY)?;
        let value = decode("state value", &entry.value, MAX_VALUE)?;
        total = total
            .checked_add(key.len() + value.len())
            .ok_or("state size overflow")?;
        if total > MAX_STATE || values.insert(key, value).is_some() {
            return Err("invalid state entries".into());
        }
    }
    Ok((
        Provider {
            crypto: RustCrypto::default(),
            storage: MemoryStorage {
                values: RwLock::new(values),
            },
        },
        snapshot,
    ))
}

fn save_snapshot(
    provider: &Provider,
    signer_public: &[u8],
    group_id: Option<&GroupId>,
    past_leaves: Vec<EpochLeaves>,
) -> Result<String, String> {
    let values = provider
        .storage
        .values
        .read()
        .map_err(|_| "state lock poisoned")?;
    if values.len() > MAX_ENTRIES {
        return Err("state has too many entries".into());
    }
    let mut pairs: Vec<_> = values.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let entries = pairs
        .into_iter()
        .map(|(key, value)| Entry {
            key: B64.encode(key),
            value: B64.encode(value),
        })
        .collect();
    let snapshot = Snapshot {
        schema: SCHEMA.into(),
        signer_public: B64.encode(signer_public),
        group_id: group_id
            .map(|g| B64.encode(g.as_slice()))
            .unwrap_or_default(),
        entries,
        past_leaves,
    };
    let raw = serde_json::to_vec(&snapshot).map_err(|_| "state serialization failed")?;
    if raw.len() > MAX_STATE {
        return Err("state snapshot exceeds bound".into());
    }
    Ok(B64.encode(raw))
}

fn signer(provider: &Provider, snapshot: &Snapshot) -> Result<SignatureKeyPair, String> {
    let public = decode("signer public key", &snapshot.signer_public, 64)?;
    SignatureKeyPair::read(provider.storage(), &public, SUITE.signature_algorithm())
        .ok_or("missing signer key".into())
}

fn group(provider: &Provider, snapshot: &Snapshot) -> Result<MlsGroup, String> {
    let id = decode("group id", &snapshot.group_id, 255)?;
    MlsGroup::load(provider.storage(), &GroupId::from_slice(&id))
        .map_err(|_| "group state load failed".to_string())?
        .ok_or("missing group state".into())
}

// member_identity returns the BasicCredential identity of a message sent by a
// current group member. Commits and application messages from any other
// sender type (external joiners, preconfigured senders) have no member leaf and
// are refused, because a room accepts content only from members.
fn member_identity(sender: &Sender, credential: &Credential) -> Result<Vec<u8>, String> {
    if !matches!(sender, Sender::Member(_)) {
        return Err("message sender is not a group member".into());
    }
    if credential.credential_type() != CredentialType::Basic {
        return Err("unsupported sender credential".into());
    }
    let identity = credential.serialized_content();
    if identity.is_empty() || identity.len() > MAX_IDENTITY {
        return Err("invalid sender identity".into());
    }
    Ok(identity.to_vec())
}

// epoch_leaves records the signature key of every leaf of the group's
// current epoch, in leaf order.
fn epoch_leaves(group: &MlsGroup) -> Result<EpochLeaves, String> {
    let mut leaves: Vec<LeafKey> = group
        .members()
        .map(|member| LeafKey {
            index: member.index.u32(),
            key: B64.encode(&member.signature_key),
        })
        .collect();
    if leaves.is_empty() || leaves.len() > MAX_LEAVES {
        return Err("group leaf count is outside its bound".into());
    }
    leaves.sort_by_key(|leaf| leaf.index);
    Ok(EpochLeaves {
        epoch: group.epoch().as_u64(),
        leaves,
    })
}

// retire_epoch appends the epoch a group is about to leave to the retained
// past epochs, keeping only as many as the group retains.
fn retire_epoch(mut past: Vec<EpochLeaves>, leaving: EpochLeaves) -> Vec<EpochLeaves> {
    past.retain(|epoch| epoch.epoch < leaving.epoch);
    past.push(leaving);
    let excess = past.len().saturating_sub(MAX_PAST_EPOCHS);
    past.drain(..excess);
    past
}

// current_leaf_key returns the signature key of `index` in the current tree.
fn current_leaf_key(group: &MlsGroup, index: LeafNodeIndex) -> Result<Vec<u8>, String> {
    group
        .member_at(index)
        .map(|member| member.signature_key)
        .ok_or_else(|| "sender leaf is not in the tree".to_string())
}

// past_leaf_key returns the signature key `index` had in a retained past
// epoch.
fn past_leaf_key(
    past: &[EpochLeaves],
    epoch: u64,
    index: LeafNodeIndex,
) -> Result<Vec<u8>, String> {
    let leaves = past
        .iter()
        .find(|retained| retained.epoch == epoch)
        .ok_or("the message epoch is not retained")?;
    let leaf = leaves
        .leaves
        .iter()
        .find(|leaf| leaf.index == index.u32())
        .ok_or("sender leaf is not in the past epoch tree")?;
    decode("past leaf key", &leaf.key, 64)
}

fn member_index(sender: &Sender) -> Result<LeafNodeIndex, String> {
    match sender {
        Sender::Member(index) => Ok(*index),
        _ => Err("message sender is not a group member".into()),
    }
}

// open decrypts one PrivateMessage of the current or a retained past epoch
// and reports its sender leaf. In compare mode the caller's authenticated data
// must equal the message's; in readback mode the caller passes none, and the
// message's own is returned only after the message opened, so an
// unauthenticated value never leaves the driver.
fn open(req: &Request, out: &mut Response, mode: AadMode) -> Result<(), String> {
    let (provider, snapshot) = load_snapshot(&req.state)?;
    let mut group = group(&provider, &snapshot)?;
    let expected = match mode {
        AadMode::Compare if req.aad.is_empty() => Vec::new(),
        AadMode::Compare => decode("aad", &req.aad, MAX_AAD)?,
        AadMode::Readback if req.aad.is_empty() => Vec::new(),
        AadMode::Readback => return Err("readback takes no authenticated data".into()),
    };
    let message: MlsMessageIn = decode_tls("message", &req.message, MAX_MESSAGE)?;
    let protocol = message
        .try_into_protocol_message()
        .map_err(|_| "message is not an MLS protocol message")?;
    let carried = match &protocol {
        ProtocolMessage::PrivateMessage(value) => value.aad().to_vec(),
        _ => return Err("application message is not private".into()),
    };
    match mode {
        AadMode::Compare if carried != expected => return Err("authenticated data mismatch".into()),
        AadMode::Readback if carried.is_empty() || carried.len() > MAX_AAD => {
            return Err("message carries no bounded authenticated data".into())
        }
        AadMode::Compare | AadMode::Readback => {}
    }
    let processed = group
        .process_message(&provider, protocol)
        .map_err(|_| "message decryption failed")?;
    let sender = member_identity(processed.sender(), processed.credential())?;
    let sender_index = member_index(processed.sender())?;
    let message_epoch = processed.epoch().as_u64();
    let sender_key = if message_epoch == group.epoch().as_u64() {
        current_leaf_key(&group, sender_index)?
    } else {
        past_leaf_key(&snapshot.past_leaves, message_epoch, sender_index)?
    };
    let plaintext = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(v) => v.into_bytes(),
        _ => return Err("message is not application data".into()),
    };
    let public = decode("signer public key", &snapshot.signer_public, 64)?;
    out.plaintext = B64.encode(plaintext);
    out.sender_identity = B64.encode(sender);
    out.sender_signature_key = B64.encode(sender_key);
    out.sender_leaf_index = Some(sender_index.u32());
    out.epoch = Some(group.epoch().as_u64());
    if mode == AadMode::Readback {
        out.aad = B64.encode(carried);
    }
    out.state = save_snapshot(
        &provider,
        &public,
        Some(group.group_id()),
        snapshot.past_leaves,
    )?;
    Ok(())
}

fn handle(req: Request) -> Result<Response, String> {
    if req.schema != SCHEMA {
        return Err("unsupported request schema".into());
    }
    let mut out = Response {
        schema: SCHEMA,
        ok: true,
        ..Default::default()
    };
    match req.op.as_str() {
        "inspect" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let group = group(&provider, &snapshot)?;
            out.group_id = B64.encode(group.group_id().as_slice());
            out.epoch = Some(group.epoch().as_u64());
            out.epoch_authenticator = B64.encode(group.epoch_authenticator().as_slice());
        }
        "export" => {
            if req.label.is_empty() || req.label.len() > 255 || req.length == 0 {
                return Err("invalid exporter request".into());
            }
            let context = if req.context.is_empty() {
                Vec::new()
            } else {
                decode("exporter context", &req.context, 4096)?
            };
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let group = group(&provider, &snapshot)?;
            let secret = group
                .export_secret(provider.crypto(), &req.label, &context, req.length as usize)
                .map_err(|_| "secret export failed")?;
            out.secret = B64.encode(secret);
            out.group_id = B64.encode(group.group_id().as_slice());
            out.epoch = Some(group.epoch().as_u64());
        }
        "validate" => {
            let expected_identity = decode("identity", &req.identity, MAX_IDENTITY)?;
            let expected_public = decode("public key", &req.public_key, 64)?;
            if expected_public.len() != 32 {
                return Err("invalid public key length".into());
            }
            let provider = Provider::default();
            let package = decode_tls::<KeyPackageIn>("key package", &req.key_package, 64 * 1024)?
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| "invalid KeyPackage")?;
            if package.ciphersuite() != SUITE
                || package.leaf_node().credential().credential_type() != CredentialType::Basic
            {
                return Err("unsupported KeyPackage profile".into());
            }
            if package.leaf_node().credential().serialized_content() != expected_identity
                || package.leaf_node().signature_key().as_slice() != expected_public
            {
                return Err("KeyPackage authority mismatch".into());
            }
        }
        "signer" => {
            // A fresh leaf signature key, before its identity exists: a relay
            // room leaf's identity names a credential that names this key.
            let provider = Provider::default();
            let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
                .map_err(|_| "signer generation failed")?;
            signer
                .store(provider.storage())
                .map_err(|_| "signer storage failed")?;
            out.public_key = B64.encode(signer.public());
            out.state = save_snapshot(&provider, signer.public(), None, Vec::new())?;
        }
        "identity" => {
            let identity = decode("identity", &req.identity, MAX_IDENTITY)?;
            // With a state, the KeyPackage is made for the signer it holds
            // (from `signer`); without one, for a fresh signer.
            let (provider, signer) = if req.state.is_empty() {
                let provider = Provider::default();
                let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
                    .map_err(|_| "signer generation failed")?;
                signer
                    .store(provider.storage())
                    .map_err(|_| "signer storage failed")?;
                (provider, signer)
            } else {
                let (provider, snapshot) = load_snapshot(&req.state)?;
                if !snapshot.group_id.is_empty() {
                    return Err("identity already belongs to a group".into());
                }
                let signer = signer(&provider, &snapshot)?;
                (provider, signer)
            };
            let credential = CredentialWithKey {
                credential: BasicCredential::new(identity).into(),
                signature_key: signer.to_public_vec().into(),
            };
            let bundle = KeyPackage::builder()
                .build(SUITE, &provider, &signer, credential)
                .map_err(|_| "KeyPackage generation failed")?;
            out.public_key = B64.encode(signer.public());
            out.key_package = encode(bundle.key_package())?;
            out.state = save_snapshot(&provider, signer.public(), None, Vec::new())?;
        }
        "create" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            if !snapshot.group_id.is_empty() {
                return Err("identity already belongs to a group".into());
            }
            let signer = signer(&provider, &snapshot)?;
            let identity = decode_tls::<KeyPackageIn>("key package", &req.key_package, 64 * 1024)?
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| "invalid own KeyPackage")?;
            if identity.ciphersuite() != SUITE
                || identity.leaf_node().credential().credential_type() != CredentialType::Basic
                || identity.leaf_node().signature_key().as_slice() != signer.public()
            {
                return Err("own KeyPackage does not match signer".into());
            }
            let credential = CredentialWithKey {
                credential: identity.leaf_node().credential().clone(),
                signature_key: signer.to_public_vec().into(),
            };
            let group_id = decode("group id", &req.group_id, 255)?;
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(SUITE)
                .use_ratchet_tree_extension(true)
                .max_past_epochs(MAX_PAST_EPOCHS)
                .sender_ratchet_configuration(sender_ratchet())
                .build();
            let group = MlsGroup::new_with_group_id(
                &provider,
                &signer,
                &config,
                GroupId::from_slice(&group_id),
                credential,
            )
            .map_err(|_| "group creation failed")?;
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(
                &provider,
                signer.public(),
                Some(group.group_id()),
                Vec::new(),
            )?;
        }
        "commit" => {
            if req.key_packages.len() + req.remove_identities.len() == 0
                || req.key_packages.len() + req.remove_identities.len() > 64
            {
                return Err("invalid member count".into());
            }
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let signer = signer(&provider, &snapshot)?;
            let mut group = group(&provider, &snapshot)?;
            let mut packages = Vec::with_capacity(req.key_packages.len());
            for value in &req.key_packages {
                let package = decode_tls::<KeyPackageIn>("key package", value, 64 * 1024)?
                    .validate(provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|_| "invalid KeyPackage")?;
                if package.ciphersuite() != SUITE
                    || package.leaf_node().credential().credential_type() != CredentialType::Basic
                {
                    return Err("unsupported KeyPackage profile".into());
                }
                packages.push(package);
            }
            let mut removals = Vec::with_capacity(req.remove_identities.len());
            for value in &req.remove_identities {
                let identity = decode("removed identity", value, MAX_IDENTITY)?;
                let matches: Vec<_> = group
                    .members()
                    .filter(|member| member.credential.serialized_content() == identity)
                    .map(|member| member.index)
                    .collect();
                if matches.len() != 1 {
                    return Err("removed identity is absent or ambiguous".into());
                }
                if removals.contains(&matches[0]) {
                    return Err("duplicate removed identity".into());
                }
                removals.push(matches[0]);
            }
            let leaving = epoch_leaves(&group)?;
            let bundle = group
                .commit_builder()
                .propose_removals(removals)
                .propose_adds(packages)
                .load_psks(provider.storage())
                .map_err(|_| "commit PSK load failed")?
                .build(provider.rand(), provider.crypto(), &signer, |_| true)
                .map_err(|_| "commit creation failed")?
                .stage_commit(&provider)
                .map_err(|_| "commit staging failed")?;
            group
                .merge_pending_commit(&provider)
                .map_err(|_| "commit merge failed")?;
            let (commit, welcome, _) = bundle.into_messages();
            out.commit = encode(&commit)?;
            if let Some(welcome) = welcome {
                out.welcome = encode(&welcome)?;
            }
            out.epoch = Some(group.epoch().as_u64());
            let past = retire_epoch(snapshot.past_leaves, leaving);
            out.state = save_snapshot(&provider, signer.public(), Some(group.group_id()), past)?;
        }
        "refresh" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let signer = signer(&provider, &snapshot)?;
            let mut group = group(&provider, &snapshot)?;
            let leaving = epoch_leaves(&group)?;
            let bundle = group
                .self_update(&provider, &signer, LeafNodeParameters::default())
                .map_err(|_| "self update failed")?;
            group
                .merge_pending_commit(&provider)
                .map_err(|_| "self update merge failed")?;
            out.commit = encode(&bundle.into_commit())?;
            out.epoch = Some(group.epoch().as_u64());
            let past = retire_epoch(snapshot.past_leaves, leaving);
            out.state = save_snapshot(&provider, signer.public(), Some(group.group_id()), past)?;
        }
        "join" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            if !snapshot.group_id.is_empty() {
                return Err("identity already belongs to a group".into());
            }
            let welcome: MlsMessageIn = decode_tls("welcome", &req.welcome, MAX_MESSAGE)?;
            let welcome = match welcome.extract() {
                MlsMessageBodyIn::Welcome(v) => v,
                _ => return Err("message is not a Welcome".into()),
            };
            let config = MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .max_past_epochs(MAX_PAST_EPOCHS)
                .sender_ratchet_configuration(sender_ratchet())
                .build();
            let staged = StagedWelcome::new_from_welcome(&provider, &config, welcome, None)
                .map_err(|_| "Welcome processing failed")?;
            // The leaf that authored the Welcome: the joiner authenticates
            // it as the authority before anything is installed.
            let sender_index = staged.welcome_sender_index();
            let sender = staged
                .welcome_sender()
                .map_err(|_| "Welcome sender is not in the tree")?;
            if sender.credential().credential_type() != CredentialType::Basic {
                return Err("unsupported Welcome sender credential".into());
            }
            let sender_identity = sender.credential().serialized_content().to_vec();
            if sender_identity.is_empty() || sender_identity.len() > MAX_IDENTITY {
                return Err("invalid Welcome sender identity".into());
            }
            let sender_key = sender.signature_key().as_slice().to_vec();
            let group = staged
                .into_group(&provider)
                .map_err(|_| "Welcome merge failed")?;
            let public = decode("signer public key", &snapshot.signer_public, 64)?;
            out.sender_identity = B64.encode(sender_identity);
            out.sender_signature_key = B64.encode(sender_key);
            out.sender_leaf_index = Some(sender_index.u32());
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(&provider, &public, Some(group.group_id()), Vec::new())?;
        }
        "apply" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let mut group = group(&provider, &snapshot)?;
            let message: MlsMessageIn = decode_tls("commit", &req.message, MAX_MESSAGE)?;
            let leaving = epoch_leaves(&group)?;
            let processed = group
                .process_message(
                    &provider,
                    message
                        .try_into_protocol_message()
                        .map_err(|_| "message is not an MLS protocol message")?,
                )
                .map_err(|_| "commit processing failed")?;
            let committer = member_identity(processed.sender(), processed.credential())?;
            let committer_index = member_index(processed.sender())?;
            let committer_key = current_leaf_key(&group, committer_index)?;
            let staged = match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(v) => v,
                _ => return Err("message is not a commit".into()),
            };
            group
                .merge_staged_commit(&provider, *staged)
                .map_err(|_| "commit merge failed")?;
            let public = decode("signer public key", &snapshot.signer_public, 64)?;
            out.sender_identity = B64.encode(committer);
            out.sender_signature_key = B64.encode(committer_key);
            out.sender_leaf_index = Some(committer_index.u32());
            out.epoch = Some(group.epoch().as_u64());
            let past = retire_epoch(snapshot.past_leaves, leaving);
            out.state = save_snapshot(&provider, &public, Some(group.group_id()), past)?;
        }
        "seal" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let signer = signer(&provider, &snapshot)?;
            let mut group = group(&provider, &snapshot)?;
            let aad = if req.aad.is_empty() {
                Vec::new()
            } else {
                decode("aad", &req.aad, MAX_AAD)?
            };
            let plaintext = decode("plaintext", &req.plaintext, MAX_MESSAGE)?;
            group.set_aad(aad);
            let message = group
                .create_message(&provider, &signer, &plaintext)
                .map_err(|_| "message encryption failed")?;
            out.message = encode(&message)?;
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(
                &provider,
                signer.public(),
                Some(group.group_id()),
                snapshot.past_leaves,
            )?;
        }
        "open" => open(&req, &mut out, AadMode::Compare)?,
        "open_readback" => open(&req, &mut out, AadMode::Readback)?,
        "members" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let group = group(&provider, &snapshot)?;
            let mut members = Vec::new();
            for member in group.members() {
                if member.credential.credential_type() != CredentialType::Basic {
                    return Err("unsupported member credential".into());
                }
                let identity = member.credential.serialized_content();
                if identity.is_empty() || identity.len() > MAX_IDENTITY {
                    return Err("invalid member identity".into());
                }
                members.push(MemberOut {
                    index: member.index.u32(),
                    identity: B64.encode(identity),
                    signature_key: B64.encode(&member.signature_key),
                });
            }
            if members.is_empty() || members.len() > MAX_LEAVES {
                return Err("group leaf count is outside its bound".into());
            }
            members.sort_by_key(|member| member.index);
            out.members = members;
            out.group_id = B64.encode(group.group_id().as_slice());
            out.epoch = Some(group.epoch().as_u64());
        }
        _ => return Err("unsupported operation".into()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(op: &str) -> Request {
        Request {
            schema: SCHEMA.into(),
            op: op.into(),
            state: String::new(),
            identity: String::new(),
            public_key: String::new(),
            group_id: String::new(),
            key_package: String::new(),
            key_packages: vec![],
            remove_identities: vec![],
            welcome: String::new(),
            message: String::new(),
            aad: String::new(),
            plaintext: String::new(),
            label: String::new(),
            context: String::new(),
            length: 0,
        }
    }

    fn identity(name: &[u8]) -> Response {
        let mut req = request("identity");
        req.identity = B64.encode(name);
        handle(req).unwrap()
    }

    #[test]
    fn three_members_chat_after_snapshot_restart() {
        let alice = identity(b"alice-authority");
        let bob = identity(b"bob-authority");
        let charlie = identity(b"charlie-authority");

        let mut validate = request("validate");
        validate.identity = B64.encode(b"bob-authority");
        validate.public_key = bob.public_key.clone();
        validate.key_package = bob.key_package.clone();
        handle(validate).unwrap();

        let mut create = request("create");
        create.state = alice.state;
        create.key_package = alice.key_package;
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let founder = handle(create).unwrap();

        let mut add = request("commit");
        add.state = founder.state;
        add.key_packages = vec![bob.key_package, charlie.key_package];
        let added = handle(add).unwrap();
        assert_eq!(added.epoch, Some(1));

        let mut bob_join = request("join");
        bob_join.state = bob.state;
        bob_join.welcome = added.welcome.clone();
        let bob_joined = handle(bob_join).unwrap();

        let mut charlie_join = request("join");
        charlie_join.state = charlie.state;
        charlie_join.welcome = added.welcome;
        let charlie_joined = handle(charlie_join).unwrap();

        // Each operation reconstructs a fresh provider exclusively from the
        // returned snapshot, so this is also a process-restart proof.
        let mut seal = request("seal");
        seal.state = bob_joined.state;
        seal.aad = B64.encode(b"room+event binding");
        seal.plaintext = B64.encode(b"hello encrypted group");
        let sealed = handle(seal).unwrap();

        let mut open = request("open");
        open.state = charlie_joined.state;
        open.aad = B64.encode(b"room+event binding");
        open.message = sealed.message.clone();
        let opened = handle(open).unwrap();
        assert_eq!(
            B64.decode(opened.plaintext).unwrap(),
            b"hello encrypted group"
        );

        let mut wrong_aad = request("open");
        wrong_aad.state = added.state;
        wrong_aad.aad = B64.encode(b"different event");
        wrong_aad.message = sealed.message;
        assert!(handle(wrong_aad).is_err());
    }

    // pair returns the states of a founder and one joined member.
    fn pair() -> (String, String) {
        let alice = identity(b"alice-authority");
        let bob = identity(b"bob-member");
        let mut create = request("create");
        create.state = alice.state;
        create.key_package = alice.key_package;
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let founder = handle(create).unwrap();
        let mut add = request("commit");
        add.state = founder.state;
        add.key_packages = vec![bob.key_package];
        let added = handle(add).unwrap();
        let mut join = request("join");
        join.state = bob.state;
        join.welcome = added.welcome;
        (added.state, handle(join).unwrap().state)
    }

    fn readback(state: &str, message: &str) -> Result<Response, String> {
        let mut open = request("open_readback");
        open.state = state.to_string();
        open.message = message.to_string();
        handle(open)
    }

    #[test]
    fn readback_returns_the_messages_own_authenticated_data() {
        let (alice, bob) = pair();
        let sealed = seal_as(&bob, b"room binding", b"hello");
        let opened = readback(&alice, &sealed.message).unwrap();
        assert_eq!(B64.decode(&opened.aad).unwrap(), b"room binding");
        assert_eq!(B64.decode(&opened.plaintext).unwrap(), b"hello");
        assert_eq!(B64.decode(&opened.sender_identity).unwrap(), b"bob-member");
        assert!(!opened.state.is_empty());
        // Compare mode never reports the authenticated data.
        let compared = open_as(&alice, b"room binding", &sealed.message).unwrap();
        assert!(compared.aad.is_empty());
    }

    #[test]
    fn readback_takes_no_authenticated_data_and_refuses_a_message_without_any() {
        let (alice, bob) = pair();
        let sealed = seal_as(&bob, b"room binding", b"hello");
        let mut both = request("open_readback");
        both.state = alice.clone();
        both.aad = B64.encode(b"room binding");
        both.message = sealed.message;
        assert!(handle(both).is_err());
        let mut bare = request("seal");
        bare.state = bob;
        bare.plaintext = B64.encode(b"no binding");
        let unbound = handle(bare).unwrap();
        assert!(readback(&alice, &unbound.message).is_err());
    }

    #[test]
    fn a_damaged_message_is_refused_in_both_modes() {
        let (alice, bob) = pair();
        let sealed = seal_as(&bob, b"room binding", b"hello");
        let mut raw = B64.decode(&sealed.message).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let damaged = B64.encode(raw);
        assert!(readback(&alice, &damaged).is_err());
        assert!(open_as(&alice, b"room binding", &damaged).is_err());
        // The state was not changed by the refusals.
        assert!(readback(&alice, &sealed.message).is_ok());
    }

    #[test]
    fn compare_refuses_another_or_an_absent_authenticated_data() {
        let (alice, bob) = pair();
        let sealed = seal_as(&bob, b"room binding", b"hello");
        assert!(open_as(&alice, b"another binding", &sealed.message).is_err());
        // An absent field is the empty value, never readback: a message
        // carrying authenticated data does not open without it.
        let mut absent = request("open");
        absent.state = alice.clone();
        absent.message = sealed.message.clone();
        assert!(handle(absent).is_err());
        assert!(open_as(&alice, b"room binding", &sealed.message).is_ok());
    }

    fn state_len(encoded: &str) -> usize {
        B64.decode(encoded).unwrap().len()
    }

    fn seal_as(state: &str, aad: &[u8], text: &[u8]) -> Response {
        let mut seal = request("seal");
        seal.state = state.to_string();
        seal.aad = B64.encode(aad);
        seal.plaintext = B64.encode(text);
        handle(seal).unwrap()
    }

    fn open_as(state: &str, aad: &[u8], message: &str) -> Result<Response, String> {
        let mut open = request("open");
        open.state = state.to_string();
        open.aad = B64.encode(aad);
        open.message = message.to_string();
        handle(open)
    }

    fn apply_as(state: &str, commit: &str) -> Response {
        let mut apply = request("apply");
        apply.state = state.to_string();
        apply.message = commit.to_string();
        handle(apply).unwrap()
    }

    // The largest BasicCredential identity a relay room leaf carries: the
    // fixed compact binding of Agent, Endpoint, device and leaf-credential
    // digest, 4 x 32 bytes (section 11.2). The identity is replicated into
    // the tree and every retained epoch, so the state bound is measured with
    // it, never with a short test name.
    const LEAF_IDENTITY_BYTES: usize = 128;

    // A distinct maximal identity for member `index`. The library's storage
    // encodes byte strings as JSON number arrays, so a byte costs up to four
    // characters ("255,"); every byte here is at least 100, the costliest
    // width, so the measurement is the upper bound for any digest values.
    fn leaf_identity(index: usize) -> Vec<u8> {
        let mut identity = vec![0xff; LEAF_IDENTITY_BYTES];
        // At most 64 leaves (the profile bound): 0x80 + 63 stays three digits.
        identity[0] = 0x80 + u8::try_from(index).expect("at most 64 leaves");
        identity
    }

    // Builds a group of `leaves` leaves in Add Commits of at most 32 (the Go
    // adapter caps one Commit at 32 leaf operations) and returns every
    // member's state, founder first. Every leaf carries a maximal identity.
    fn full_group(leaves: usize) -> Vec<String> {
        try_full_group(leaves).unwrap()
    }

    // full_group, reporting the driver's refusal instead of panicking: a
    // group above the relay room bound may exceed the state bound while it
    // is being built.
    fn try_full_group(leaves: usize) -> Result<Vec<String>, String> {
        let names: Vec<Vec<u8>> = (0..leaves).map(leaf_identity).collect();
        let ids: Vec<Response> = names.iter().map(|n| identity(n)).collect();
        let mut create = request("create");
        create.state = ids[0].state.clone();
        create.key_package = ids[0].key_package.clone();
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let mut states = vec![handle(create)?.state];
        let batches: Vec<std::ops::Range<usize>> = (1..leaves)
            .step_by(32)
            .map(|start| start..(start + 32).min(leaves))
            .collect();
        for batch in batches {
            let mut add = request("commit");
            add.state = states[0].clone();
            add.key_packages = batch.clone().map(|i| ids[i].key_package.clone()).collect();
            let added = handle(add)?;
            for existing in 1..states.len() {
                let mut apply = request("apply");
                apply.state = states[existing].clone();
                apply.message = added.commit.clone();
                states[existing] = handle(apply)?.state;
            }
            states[0] = added.state;
            for i in batch {
                let mut join = request("join");
                join.state = ids[i].state.clone();
                join.welcome = added.welcome.clone();
                states.push(handle(join)?.state);
            }
        }
        Ok(states)
    }

    fn refresh_all(states: &mut [String]) -> String {
        let mut refresh = request("refresh");
        refresh.state = states[0].clone();
        let refreshed = handle(refresh).unwrap();
        for state in states.iter_mut().skip(1) {
            *state = apply_as(state, &refreshed.commit).state;
        }
        states[0] = refreshed.state;
        refreshed.commit
    }

    // Runs `epochs` epochs of traffic. In each, every member but the observer
    // seals `per_sender` messages; the observer opens all of them in order, or
    // only the last when `skip` is set, which leaves `per_sender - 1` skipped
    // keys in that sender's ratchet. Returns the largest state seen and the
    // observer's final state.
    fn traffic(
        states: &mut [String],
        epochs: usize,
        per_sender: usize,
        skip: bool,
    ) -> Result<usize, String> {
        let observer = 1usize;
        let aad = b"room binding";
        let mut largest = 0usize;
        for _ in 0..epochs {
            for sender in 0..states.len() {
                if sender == observer {
                    continue;
                }
                for index in 0..per_sender {
                    let mut seal = request("seal");
                    seal.state = states[sender].clone();
                    seal.aad = B64.encode(aad);
                    seal.plaintext = B64.encode(b"m");
                    let sealed = handle(seal)?;
                    states[sender] = sealed.state;
                    if !skip || index + 1 == per_sender {
                        states[observer] = open_as(&states[observer], aad, &sealed.message)?.state;
                    }
                }
            }
            for state in states.iter() {
                largest = largest.max(state_len(state));
            }
            // A refresh over the bound is the driver's refusal, reported.
            let mut refresh = request("refresh");
            refresh.state = states[0].clone();
            let refreshed = handle(refresh)?;
            for state in states.iter_mut().skip(1) {
                let mut apply = request("apply");
                apply.state = state.clone();
                apply.message = refreshed.commit.clone();
                *state = handle(apply)?.state;
            }
            states[0] = refreshed.state;
        }
        Ok(largest)
    }

    // The relay room bound is 32 Agents with one device each: 32 leaves.
    const RELAY_ROOM_LEAVES: usize = 32;

    // The worst case the configuration allows at the relay room bound: in the
    // current and both retained epochs every other member's ratchet holds the
    // most skipped keys the tolerance keeps. It must fit the 512 KiB state
    // bound, two 262,144-byte journal chunks, with at least 20 % headroom.
    #[test]
    fn worst_case_state_fits_at_the_relay_room_bound() {
        let mut in_order = full_group(RELAY_ROOM_LEAVES);
        let base = traffic(&mut in_order, MAX_PAST_EPOCHS + 2, 1, false).unwrap();
        let mut skipping = full_group(RELAY_ROOM_LEAVES);
        let per_sender = OUT_OF_ORDER_TOLERANCE as usize + 1;
        let worst = traffic(&mut skipping, MAX_PAST_EPOCHS + 2, per_sender, true).unwrap();
        eprintln!(
            "32 leaves, {LEAF_IDENTITY_BYTES}-byte identities: in-order {base} bytes, maximal skipped keys {worst} bytes, bound {MAX_STATE}"
        );
        assert!(
            worst <= MAX_STATE * 4 / 5,
            "{worst} leaves less than 20 % of {MAX_STATE}"
        );
        assert!(worst.div_ceil(262_144) <= 2);
    }

    // A sender far ahead (one message just inside the forward distance) costs
    // the receiver no more stored keys than the tolerance allows; one beyond
    // it is refused.
    //
    // The library stores byte strings as JSON number arrays, so a key of
    // random bytes costs 1 to 3 characters per byte: two states holding the
    // same number of keys differ by tens of bytes (over 200 runs the jump and
    // the tolerance growth differed by -52 to +60 bytes, mean +4.5, the wider
    // generation numbers of a jump adding only a few). So the jump is held to
    // "at most the tolerance's keys", one key's cost being the margin, and to
    // far below what keeping every skipped key would cost.
    #[test]
    fn forward_jump_keeps_only_the_tolerance() {
        let aad = b"room binding";
        let growth = |skipped: usize| -> (usize, Result<Response, String>) {
            let states = full_group(4);
            let mut sender = states[2].clone();
            let mut last = String::new();
            for _ in 0..=skipped {
                let sealed = seal_as(&sender, aad, b"m");
                sender = sealed.state;
                last = sealed.message;
            }
            (state_len(&states[1]), open_as(&states[1], aad, &last))
        };
        let measured = |skipped: usize| -> usize {
            let (before, opened) = growth(skipped);
            state_len(&opened.unwrap().state) - before
        };
        let tolerance = OUT_OF_ORDER_TOLERANCE as usize;
        let jump_growth = measured(MAXIMUM_FORWARD_DISTANCE as usize);
        let tolerance_growth = measured(tolerance);
        let in_order_growth = measured(0);
        // The cost of one kept key: the tolerance's keys over in-order traffic.
        let per_key = tolerance_growth.saturating_sub(in_order_growth) / tolerance;
        eprintln!("forward jump of {MAXIMUM_FORWARD_DISTANCE}: +{jump_growth} bytes; skip of {tolerance}: +{tolerance_growth} bytes; in order: +{in_order_growth} bytes; one key: {per_key} bytes");
        assert!(per_key > 0, "skipping keys stored nothing");
        assert!(
            jump_growth < tolerance_growth + per_key,
            "a jump of {MAXIMUM_FORWARD_DISTANCE} kept more than {tolerance} keys: +{jump_growth} vs +{tolerance_growth}, one key {per_key}"
        );
        assert!(
            jump_growth * 4 < MAXIMUM_FORWARD_DISTANCE as usize * per_key,
            "a jump of {MAXIMUM_FORWARD_DISTANCE} costs near every skipped key: +{jump_growth}"
        );
        let (_, beyond) = growth(MAXIMUM_FORWARD_DISTANCE as usize + 1);
        assert!(beyond.is_err());
    }

    // The driver refuses an operation whose state would exceed the bound
    // rather than return a state the journal cannot hold. The profile allows
    // 64 leaves (several devices per Agent, not carried over the relay), and
    // there the same maximal skipping exceeds 512 KiB.
    #[test]
    fn state_over_bound_fails_closed() {
        // With maximal identities a 64-leaf group may already exceed the
        // bound while it is built; either way the driver refuses the state.
        let error = match try_full_group(64) {
            Err(error) => error,
            Ok(mut states) => {
                let per_sender = OUT_OF_ORDER_TOLERANCE as usize + 1;
                traffic(&mut states, MAX_PAST_EPOCHS + 1, per_sender, true).unwrap_err()
            }
        };
        assert_eq!(error, "state snapshot exceeds bound");
    }

    #[test]
    fn past_epochs_open_and_report_the_sender() {
        let alice = identity(b"alice-authority");
        let bob = identity(b"bob-member");
        let alice_key = alice.public_key.clone();
        let bob_key = bob.public_key.clone();
        let mut create = request("create");
        create.state = alice.state;
        create.key_package = alice.key_package;
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let founder = handle(create).unwrap();
        let mut add = request("commit");
        add.state = founder.state;
        add.key_packages = vec![bob.key_package];
        let added = handle(add).unwrap();
        let mut join = request("join");
        join.state = bob.state;
        join.welcome = added.welcome;
        let mut states = vec![added.state, handle(join).unwrap().state];

        let authenticators = |states: &[String]| -> Vec<String> {
            states
                .iter()
                .map(|state| {
                    let mut inspect = request("inspect");
                    inspect.state = state.clone();
                    handle(inspect).unwrap().epoch_authenticator
                })
                .collect()
        };
        let first = authenticators(&states);
        assert!(!first[0].is_empty());
        assert_eq!(first[0], first[1]);

        let aad = b"room binding";
        let sealed = seal_as(&states[1], aad, b"before the commits");
        states[1] = sealed.state;
        let mut refresh = request("refresh");
        refresh.state = states[0].clone();
        let refreshed = handle(refresh).unwrap();
        let applied = apply_as(&states[1], &refreshed.commit);
        assert_eq!(
            B64.decode(&applied.sender_identity).unwrap(),
            b"alice-authority"
        );
        // The committer's leaf signature key is the authority's own.
        assert_eq!(applied.sender_signature_key, alice_key);
        assert_eq!(applied.sender_leaf_index, Some(0));
        states = vec![refreshed.state, applied.state];
        let second = authenticators(&states);
        assert_eq!(second[0], second[1]);
        assert_ne!(first[0], second[0]);
        refresh_all(&mut states);

        // Two epochs later the message is still opened, and names its sender.
        let opened = open_as(&states[0], aad, &sealed.message).unwrap();
        assert_eq!(
            B64.decode(&opened.plaintext).unwrap(),
            b"before the commits"
        );
        assert_eq!(B64.decode(&opened.sender_identity).unwrap(), b"bob-member");
        // Opened two epochs late, it still names the key that sealed it.
        assert_eq!(opened.sender_signature_key, bob_key);
        assert_eq!(opened.sender_leaf_index, Some(1));
        let current = seal_as(&states[1], aad, b"in the current epoch");
        let opened_now = open_as(&states[0], aad, &current.message).unwrap();
        assert_eq!(opened_now.sender_signature_key, bob_key);

        // A third epoch is beyond max_past_epochs and fails.
        let late = seal_as(&states[1], aad, b"sealed at the older epoch");
        let state_before = states[0].clone();
        refresh_all(&mut states);
        refresh_all(&mut states);
        refresh_all(&mut states);
        assert!(open_as(&states[0], aad, &late.message).is_err());
        assert!(open_as(&state_before, aad, &late.message).is_ok());
    }

    // A leaf signature key made first gets its KeyPackage later, under an
    // identity that may name it; the KeyPackage carries exactly that key.
    #[test]
    fn signer_then_identity_keeps_the_key() {
        let signer = handle(request("signer")).unwrap();
        assert!(signer.key_package.is_empty());
        let mut made = request("identity");
        made.state = signer.state.clone();
        made.identity = B64.encode(leaf_identity(3));
        let made = handle(made).unwrap();
        assert_eq!(made.public_key, signer.public_key);
        let mut validate = request("validate");
        validate.identity = B64.encode(leaf_identity(3));
        validate.public_key = signer.public_key.clone();
        validate.key_package = made.key_package.clone();
        handle(validate).unwrap();
        // The identity's KeyPackage joins a group like any other.
        let founder = identity(&leaf_identity(0));
        let mut create = request("create");
        create.state = founder.state;
        create.key_package = founder.key_package;
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let mut add = request("commit");
        add.state = handle(create).unwrap().state;
        add.key_packages = vec![made.key_package];
        let added = handle(add).unwrap();
        let mut join = request("join");
        join.state = made.state.clone();
        join.welcome = added.welcome;
        let joined = handle(join).unwrap();
        // A state that already holds a group makes no new identity.
        let mut again = request("identity");
        again.state = joined.state;
        again.identity = B64.encode(leaf_identity(4));
        assert!(handle(again).is_err());
    }

    // `members` reports every leaf of the current tree, in leaf order, with
    // its identity and signature key, and changes nothing.
    #[test]
    fn members_reports_every_leaf() {
        let states = full_group(3);
        let mut members = request("members");
        members.state = states[1].clone();
        let listed = handle(members).unwrap();
        assert!(listed.state.is_empty());
        assert_eq!(listed.members.len(), 3);
        for (position, member) in listed.members.iter().enumerate() {
            assert_eq!(member.index as usize, position);
            assert_eq!(
                B64.decode(&member.identity).unwrap(),
                leaf_identity(position)
            );
            assert_eq!(B64.decode(&member.signature_key).unwrap().len(), 32);
        }
        // The key `members` reports is the one `open` reports for that leaf.
        let aad = b"room binding";
        let sealed = seal_as(&states[2], aad, b"m");
        let opened = open_as(&states[1], aad, &sealed.message).unwrap();
        assert_eq!(opened.sender_signature_key, listed.members[2].signature_key);
        let mut without_group = request("members");
        without_group.state = identity(b"no group").state;
        assert!(handle(without_group).is_err());
    }

    // A message opened in a past epoch reports the key its sender's leaf had
    // in that epoch, even after the sender was removed and another member
    // took its leaf index.
    #[test]
    fn past_epoch_sender_key_survives_index_reuse() {
        let alice = identity(b"alice-authority");
        let bob = identity(b"bob-member");
        let carol = identity(b"carol-member");
        let bob_key = bob.public_key.clone();
        let mut create = request("create");
        create.state = alice.state;
        create.key_package = alice.key_package;
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let mut add = request("commit");
        add.state = handle(create).unwrap().state;
        add.key_packages = vec![bob.key_package];
        let added = handle(add).unwrap();
        let mut join = request("join");
        join.state = bob.state;
        join.welcome = added.welcome;
        let bob_state = handle(join).unwrap().state;
        let aad = b"room binding";
        let sealed = seal_as(&bob_state, aad, b"sealed by bob");
        // Remove Bob and add Carol in one Commit: Carol takes leaf index 1.
        let mut replace = request("commit");
        replace.state = added.state;
        replace.remove_identities = vec![B64.encode(b"bob-member")];
        replace.key_packages = vec![carol.key_package.clone()];
        let replaced = handle(replace).unwrap();
        let mut members = request("members");
        members.state = replaced.state.clone();
        let listed = handle(members).unwrap();
        assert_eq!(listed.members[1].index, 1);
        assert_eq!(listed.members[1].signature_key, carol.public_key);
        let opened = open_as(&replaced.state, aad, &sealed.message).unwrap();
        assert_eq!(B64.decode(&opened.sender_identity).unwrap(), b"bob-member");
        assert_eq!(opened.sender_leaf_index, Some(1));
        assert_eq!(opened.sender_signature_key, bob_key);
    }

    // A member that applied the authority's remove-and-add Commit opens a
    // message sealed in the earlier epoch and reports the key the sender had
    // then, not the key of the member that took its leaf index: `apply`
    // retires the tree the member held before the Commit.
    #[test]
    fn member_applying_a_commit_keeps_the_past_epoch_key() {
        let alice = identity(b"alice-authority");
        let bob = identity(b"bob-member");
        let carol = identity(b"carol-member");
        let dave = identity(b"dave-member");
        let carol_key = carol.public_key.clone();
        let mut create = request("create");
        create.state = alice.state;
        create.key_package = alice.key_package;
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let mut add = request("commit");
        add.state = handle(create).unwrap().state;
        add.key_packages = vec![bob.key_package, carol.key_package];
        let added = handle(add).unwrap();
        let joined = |state: String| -> String {
            let mut join = request("join");
            join.state = state;
            join.welcome = added.welcome.clone();
            handle(join).unwrap().state
        };
        let bob_state = joined(bob.state);
        let carol_state = joined(carol.state);
        let aad = b"room binding";
        let sealed = seal_as(&carol_state, aad, b"sealed by carol");
        // The authority removes Carol and adds Dave, who takes her index.
        let mut replace = request("commit");
        replace.state = added.state;
        replace.remove_identities = vec![B64.encode(b"carol-member")];
        replace.key_packages = vec![dave.key_package.clone()];
        let replaced = handle(replace).unwrap();
        let bob_after = apply_as(&bob_state, &replaced.commit);
        let mut members = request("members");
        members.state = bob_after.state.clone();
        let listed = handle(members).unwrap();
        assert_eq!(listed.members[2].index, 2);
        assert_eq!(listed.members[2].signature_key, dave.public_key);
        let opened = open_as(&bob_after.state, aad, &sealed.message).unwrap();
        assert_eq!(
            B64.decode(&opened.sender_identity).unwrap(),
            b"carol-member"
        );
        assert_eq!(opened.sender_leaf_index, Some(2));
        assert_eq!(opened.sender_signature_key, carol_key);
    }

    // `join` reports the leaf that authored the Welcome: the authority's.
    #[test]
    fn join_reports_the_welcome_sender() {
        let alice = identity(b"alice-authority");
        let bob = identity(b"bob-member");
        let mut create = request("create");
        create.state = alice.state;
        create.key_package = alice.key_package;
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let mut add = request("commit");
        add.state = handle(create).unwrap().state;
        add.key_packages = vec![bob.key_package];
        let added = handle(add).unwrap();
        let mut join = request("join");
        join.state = bob.state;
        join.welcome = added.welcome;
        let joined = handle(join).unwrap();
        assert_eq!(
            B64.decode(&joined.sender_identity).unwrap(),
            b"alice-authority"
        );
        assert_eq!(joined.sender_signature_key, alice.public_key);
        assert_eq!(joined.sender_leaf_index, Some(0));
    }

    // A state whose retained past-epoch keys break their bounds is refused.
    #[test]
    fn past_epoch_keys_are_bounded_on_load() {
        let mut states = full_group(2);
        refresh_all(&mut states);
        refresh_all(&mut states);
        refresh_all(&mut states);
        let raw = B64.decode(&states[1]).unwrap();
        let mut snapshot: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            snapshot["past_leaves"].as_array().unwrap().len(),
            MAX_PAST_EPOCHS
        );
        let mut inspect = request("inspect");
        inspect.state = states[1].clone();
        assert!(handle(inspect).is_ok());
        let corruptions: Vec<Box<dyn Fn(&mut serde_json::Value)>> = vec![
            // A third retained epoch, in order: one more than the group keeps.
            Box::new(|value| {
                let mut older = value["past_leaves"][0].clone();
                older["epoch"] = serde_json::json!(older["epoch"].as_u64().unwrap() - 1);
                value["past_leaves"]
                    .as_array_mut()
                    .unwrap()
                    .insert(0, older);
            }),
            Box::new(|value| {
                let first = value["past_leaves"][0].clone();
                value["past_leaves"].as_array_mut().unwrap().push(first);
            }),
            Box::new(|value| value["past_leaves"].as_array_mut().unwrap().reverse()),
            Box::new(|value| value["past_leaves"][0]["leaves"] = serde_json::json!([])),
            Box::new(|value| {
                value["past_leaves"][0]["leaves"][0]["key"] = serde_json::json!("AA==")
            }),
        ];
        for corrupt in corruptions {
            let mut changed = snapshot.clone();
            corrupt(&mut changed);
            let mut inspect = request("inspect");
            inspect.state = B64.encode(serde_json::to_vec(&changed).unwrap());
            assert!(handle(inspect).is_err());
        }
        snapshot["past_leaves"] = serde_json::json!([]);
        let mut inspect = request("inspect");
        inspect.state = B64.encode(serde_json::to_vec(&snapshot).unwrap());
        assert!(handle(inspect).is_ok());
    }

    #[test]
    fn rejects_authority_substitution_and_corrupt_snapshot() {
        let member = identity(b"member-one");
        let mut validate = request("validate");
        validate.identity = B64.encode(b"member-two");
        validate.public_key = member.public_key;
        validate.key_package = member.key_package;
        assert!(handle(validate).is_err());

        let mut corrupt = request("create");
        corrupt.state = B64
            .encode(br#"{"schema":"tos.openmls.sidecar.v1","signer_public":"AA==","entries":[]}"#);
        corrupt.key_package = B64.encode(b"not a key package");
        corrupt.group_id = B64.encode(b"group");
        assert!(handle(corrupt).is_err());
    }
}

fn main() {
    let mut raw = Vec::new();
    let result = io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "request read failed".to_string())
        .and_then(|_| {
            if raw.len() as u64 > MAX_REQUEST {
                Err("request exceeds bound".into())
            } else {
                serde_json::from_slice::<Request>(&raw).map_err(|_| "invalid request".into())
            }
        })
        .and_then(handle);
    let response = match result {
        Ok(v) => v,
        Err(error) => Response {
            schema: SCHEMA,
            ok: false,
            error,
            ..Default::default()
        },
    };
    if serde_json::to_writer(io::stdout(), &response).is_err() {
        std::process::exit(2);
    }
    if !response.ok {
        std::process::exit(1);
    }
}
