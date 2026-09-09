// SPDX-FileCopyrightText: 2026 kenway214
// SPDX-License-Identifier: Apache-2.0

use crate::utils::{AndroidUserId, AppUid};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Certificate::Certificate, KeyCreationResult::KeyCreationResult,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
    Tag::Tag,
};
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use binder::{self, Strong};
use keystore2_crypto::{
    certificate_public_key_family, certificate_signature_key_family,
    certificate_tbs_signature_key_family, extract_attestation_patchlevels,
    generate_software_attested_key, parse_issuer_from_certificate,
    parse_subject_from_certificate, resign_leaf_certificate, verify_certificate_signed_by,
};
use log::{info, warn};
use rustutils::android::system_properties;

use packagemanager_aidl::aidl::android::content::pm::IPackageManagerNative::IPackageManagerNative;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
const RUNTIME_CONFIG_PATH: &str = "/data/system/keystore_compat/config.conf";
const LEGACY_RUNTIME_CONFIG_PATH: &str = "/data/system/tee_simulator/config.conf";

pub(crate) const BLOB_MARKER: &[u8] = b"KMCPTkey\x00";
pub(crate) const LEGACY_BLOB_MARKER: &[u8] = b"TEESIMkm\x00";

#[allow(dead_code)]
pub(crate) fn is_simulated_blob(blob: &[u8]) -> bool {
    blob.starts_with(BLOB_MARKER) || blob.starts_with(LEGACY_BLOB_MARKER)
}

pub(crate) fn mark_simulated_blob(blob: Vec<u8>) -> Vec<u8> {
    let mut marked = Vec::with_capacity(BLOB_MARKER.len() + blob.len());
    marked.extend_from_slice(BLOB_MARKER);
    marked.extend(blob);
    marked
}

#[allow(dead_code)]
pub(crate) fn strip_simulated_blob(blob: &[u8]) -> &[u8] {
    if blob.starts_with(BLOB_MARKER) {
        &blob[BLOB_MARKER.len()..]
    } else if blob.starts_with(LEGACY_BLOB_MARKER) {
        &blob[LEGACY_BLOB_MARKER.len()..]
    } else {
        blob
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GeneratedAttestKeyRecord {
    alias: String,
    nspace: i64,
    source: &'static str,
}

static GENERATED_ATTEST_KEYS: LazyLock<Mutex<HashMap<i64, Vec<GeneratedAttestKeyRecord>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TRACKED_ATTEST_KEY_ALGORITHM: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TRACKED_ATTEST_KEY_MATERIAL: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TRACKED_ATTEST_SIGNERS: LazyLock<Mutex<HashMap<String, TrackedAttestSignerState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompatAttestMode {
    Patch,
    Generate,
    Auto,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompatAttestAction {
    Skip,
    PatchExistingChain,
    GenerateSoftwareChain,
}

#[derive(Debug)]
struct CompatAttestConfig {
    enabled: bool,
    mode: CompatAttestMode,
    keybox_path: String,
    target_packages: HashMap<String, Option<CompatAttestMode>>,
}

#[derive(Clone, Debug)]
struct KeyboxMaterial {
    certs: Vec<Vec<u8>>,
    signing_key: Option<Vec<u8>>,
    algorithm: Option<String>,
}

#[derive(Clone, Debug)]
struct TrackedAttestSignerState {
    signer_cert: Vec<u8>,
    signer_key: Vec<u8>,
    algorithm: Option<String>,
}

fn parse_bool_setting(value: Option<String>) -> bool {
    match value.as_deref() {
        Some("1") => true,
        Some(v) if v.eq_ignore_ascii_case("true") => true,
        _ => false,
    }
}

fn parse_mode_setting(value: Option<String>) -> CompatAttestMode {
    match value
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("generate") => CompatAttestMode::Generate,
        Some("auto") => CompatAttestMode::Auto,
        _ => CompatAttestMode::Patch,
    }
}

fn parse_target_packages(value: Option<String>) -> HashMap<String, Option<CompatAttestMode>> {
    let mut map = HashMap::new();
    for token in value.unwrap_or_default().split(['|', ',', '\n']) {
        let s = token.trim();
        if s.is_empty() {
            continue;
        }
        if let Some(pkg) = s.strip_suffix('?') {
            map.insert(pkg.trim().to_string(), Some(CompatAttestMode::Patch));
        } else if let Some(pkg) = s.strip_suffix('!') {
            map.insert(pkg.trim().to_string(), Some(CompatAttestMode::Generate));
        } else {
            map.insert(s.to_string(), None);
        }
    }
    map
}

fn get_target_mode_for_packages(
    cfg: &CompatAttestConfig,
    packages: &[String],
) -> Option<CompatAttestMode> {
    for pkg in packages {
        if let Some(override_mode) = cfg.target_packages.get(pkg) {
            return Some(override_mode.unwrap_or(cfg.mode));
        }
    }
    None
}

fn load_config_for_user(_user: AndroidUserId) -> Result<CompatAttestConfig> {
    load_config_from_runtime_file()
}

fn load_config_from_runtime_file() -> Result<CompatAttestConfig> {
    let content = fs::read_to_string(RUNTIME_CONFIG_PATH)
        .or_else(|_| fs::read_to_string(LEGACY_RUNTIME_CONFIG_PATH))
        .with_context(|| format!("read runtime config {} or {}", RUNTIME_CONFIG_PATH, LEGACY_RUNTIME_CONFIG_PATH))?;

    let mut enabled = false;
    let mut mode = CompatAttestMode::Patch;
    let mut keybox_path = String::new();
    let mut target_packages = HashMap::new();

    for line in content.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let value = v.trim();
        match k.trim() {
            "enabled" => enabled = parse_bool_setting(Some(value.to_string())),
            "mode" => mode = parse_mode_setting(Some(value.to_string())),
            "target_packages" => {
                target_packages = parse_target_packages(Some(value.to_string()));
            }
            "keybox_path" => keybox_path = value.to_string(),
            _ => {}
        }
    }

    let active = enabled && !keybox_path.is_empty();
    let _ = system_properties::write("sys.keystore_compat.active", if active { "1" } else { "0" });
    let _ = system_properties::write("sys.tee_simulator.active", if active { "1" } else { "0" });

    Ok(CompatAttestConfig {
        enabled,
        mode,
        keybox_path,
        target_packages,
    })
}

fn decide_action_for_mode(
    enabled: bool,
    mode: CompatAttestMode,
    _is_attest_key_request: bool,
    has_original_chain: bool,
) -> CompatAttestAction {
    if !enabled {
        return CompatAttestAction::Skip;
    }

    match mode {
        CompatAttestMode::Patch => {
            if has_original_chain {
                CompatAttestAction::PatchExistingChain
            } else {
                CompatAttestAction::Skip
            }
        }
        CompatAttestMode::Generate => CompatAttestAction::GenerateSoftwareChain,
        CompatAttestMode::Auto => {
            if has_original_chain {
                CompatAttestAction::PatchExistingChain
            } else {
                CompatAttestAction::GenerateSoftwareChain
            }
        }
    }
}


fn is_attest_key_request(params: &[KeyParameter]) -> bool {
    params.iter().any(|p| {
        p.tag == Tag::PURPOSE
            && matches!(p.value, KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY))
    })
}

fn has_attestation_challenge(params: &[KeyParameter]) -> bool {
    params.iter().any(|p| p.tag == Tag::ATTESTATION_CHALLENGE)
}

fn normalize_alias(alias: Option<&str>) -> Option<String> {
    let value = alias.unwrap_or_default().trim();
    if value.is_empty() { None } else { Some(value.to_string()) }
}

fn make_uid_alias_key(uid: AppUid, alias: &str) -> String {
    format!("{}:{}", uid.0, alias)
}

pub(crate) fn mark_generated_attest_key_for_uid(
    caller_uid: AppUid,
    key: &KeyDescriptor,
    creation_params: &[KeyParameter],
    used_software_generation: bool,
) {
    if !is_attest_key_request(creation_params) {
        return;
    }
    if key.domain != Domain::APP && key.domain != Domain::SELINUX {
        return;
    }
    let Some(alias) = normalize_alias(key.alias.as_deref()) else {
        return;
    };

    let source = if used_software_generation { "software" } else { "hardware" };
    let record = GeneratedAttestKeyRecord { alias: alias.clone(), nspace: key.nspace, source };
    let Ok(mut cache) = GENERATED_ATTEST_KEYS.lock() else {
        warn!("tee soft debug: failed to lock generated-attest-key cache");
        return;
    };
    let records = cache.entry(caller_uid.0).or_default();
    if records.iter().any(|r| r.alias == alias && r.nspace == key.nspace && r.source == source) {
        return;
    }
    records.push(record);
    info!(
        "tee soft debug: tracked ATTEST_KEY generation for uid={:?}, alias={}, nspace={}, source={}",
        caller_uid,
        alias,
        key.nspace,
        source
    );
}

pub(crate) fn uses_tracked_attest_key_for_uid(
    caller_uid: AppUid,
    attest_key_descriptor: Option<&KeyDescriptor>,
) -> bool {
    let Some(descriptor) = attest_key_descriptor else {
        return false;
    };
    let Some(alias) = normalize_alias(descriptor.alias.as_deref()) else {
        return false;
    };

    let Ok(cache) = GENERATED_ATTEST_KEYS.lock() else {
        warn!("tee soft debug: failed to lock generated-attest-key cache for lookup");
        return false;
    };
    let Some(records) = cache.get(&caller_uid.0) else {
        return false;
    };

    records.iter().any(|r| {
        if descriptor.domain == Domain::APP || descriptor.domain == Domain::SELINUX {
            r.alias == alias
        } else {
            r.alias == alias && r.nspace == descriptor.nspace
        }
    })
}

pub(crate) fn should_treat_external_attest_key_as_compat_for_uid(
    caller_uid: AppUid,
    creation_params: &[KeyParameter],
    attest_key_descriptor: Option<&KeyDescriptor>,
) -> bool {
    let Some(descriptor) = attest_key_descriptor else {
        return false;
    };
    if !has_attestation_challenge(creation_params) {
        return false;
    }
    if normalize_alias(descriptor.alias.as_deref()).is_none() {
        return false;
    }

    let cfg = match load_config_for_user(caller_uid.owning_user()) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(
                "tee soft debug: failed to load config while deciding external-attest soft-debug ownership for uid {:?}: {:?}",
                caller_uid, e
            );
            return false;
        }
    };
    if !cfg.enabled || cfg.target_packages.is_empty() {
        return false;
    }

    let uid_packages = match package_names_for_uid(caller_uid) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "tee soft debug: failed to query packages while deciding external-attest soft-debug ownership for uid {:?}: {:?}",
                caller_uid, e
            );
            return false;
        }
    };
    uid_packages.iter().any(|pkg| cfg.target_packages.contains_key(pkg))
}

pub(crate) fn should_force_software_generation_for_uid(
    caller_uid: AppUid,
    creation_params: &[KeyParameter],
    _has_external_attestation_key: bool,
    _uses_tracked_attest_key: bool,
) -> bool {
    let cfg = match load_config_for_user(caller_uid.owning_user()) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(
                "tee soft debug: failed to load config while deciding generation path for uid {:?}: {:?}",
                caller_uid, e
            );
            return false;
        }
    };

    if !cfg.enabled || cfg.target_packages.is_empty() {
        return false;
    }

    let uid_packages = match package_names_for_uid(caller_uid) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "tee soft debug: failed to query packages while deciding generation path for uid {:?}: {:?}",
                caller_uid, e
            );
            return false;
        }
    };
    let matched = uid_packages.iter().any(|pkg| cfg.target_packages.contains_key(pkg));
    if !matched {
        return false;
    }

    let has_challenge = has_attestation_challenge(creation_params);
    if !has_challenge {
        return false;
    }

    let target_mode = get_target_mode_for_packages(&cfg, &uid_packages).unwrap_or(cfg.mode);
    match target_mode {
        CompatAttestMode::Generate => true,
        CompatAttestMode::Patch | CompatAttestMode::Auto => false,
    }
}

pub(crate) fn generate_software_key_for_uid(
    caller_uid: AppUid,
    creation_params: &[KeyParameter],
    key_alias: Option<&str>,
) -> Result<Option<KeyCreationResult>> {
    let cfg = match load_config_for_user(caller_uid.owning_user()) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("[KEYSTORE_COMPAT] Failed to load config for software gen: {:?}", e);
            return Ok(None);
        }
    };

    if !cfg.enabled || cfg.target_packages.is_empty() || cfg.keybox_path.trim().is_empty() {
        return Ok(None);
    }

    let uid_packages = match package_names_for_uid(caller_uid) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if !uid_packages.iter().any(|pkg| cfg.target_packages.contains_key(pkg)) {
        return Ok(None);
    }

    let keybox_path = Path::new(cfg.keybox_path.trim());
    let materials = match load_keybox_material(keybox_path) {
        Ok(m) => m,
        Err(e) => {
            warn!("[KEYSTORE_COMPAT] Failed to parse keybox {}: {:?}", keybox_path.display(), e);
            return Ok(None);
        }
    };

    let is_attest_key = is_attest_key_request(creation_params);
    let requested_algorithm = creation_params
        .iter()
        .find(|p| p.tag == Tag::ALGORITHM)
        .and_then(|p| match p.value {
            KeyParameterValue::Algorithm(Algorithm::RSA) => Some("rsa"),
            KeyParameterValue::Algorithm(Algorithm::EC) => Some("ec"),
            _ => None,
        });
    let key_type = if requested_algorithm == Some("rsa") { 1 } else { 2 };
    let rsa_size = creation_params
        .iter()
        .find(|p| p.tag == Tag::KEY_SIZE)
        .and_then(|p| match p.value {
            KeyParameterValue::Integer(s) => Some(s),
            _ => None,
        })
        .unwrap_or(2048);
    let challenge = creation_params
        .iter()
        .find(|p| p.tag == Tag::ATTESTATION_CHALLENGE)
        .and_then(|p| match &p.value {
            KeyParameterValue::Blob(b) => Some(b.as_slice()),
            _ => None,
        })
        .unwrap_or(b"attest_challenge");

    let target_material = materials.iter().find(|m| {
        if key_type == 1 {
            normalize_algorithm_family(m.algorithm.as_deref()) == Some("rsa")
        } else {
            normalize_algorithm_family(m.algorithm.as_deref()) == Some("ec")
        }
    }).or_else(|| materials.first());

    let Some(material) = target_material else {
        warn!("[KEYSTORE_COMPAT] No keybox material available for software generation");
        return Ok(None);
    };

    let (Some(signing_cert), Some(signing_key)) = (material.certs.first(), material.signing_key.as_ref()) else {
        warn!("[KEYSTORE_COMPAT] Keybox material missing cert or signing key");
        return Ok(None);
    };

    match generate_software_attested_key(
        key_type,
        rsa_size,
        challenge,
        signing_cert,
        signing_key,
        is_attest_key,
    ) {
        Ok((privkey, cert)) => {
            let marked_blob = mark_simulated_blob(privkey.clone());
            let mut full_chain = vec![Certificate { encodedCertificate: cert.clone() }];
            for c in &material.certs {
                full_chain.push(Certificate { encodedCertificate: c.clone() });
            }

            if is_attest_key {
                if let Some(alias) = normalize_alias(key_alias) {
                    track_attest_key_algorithm(caller_uid, &alias, if key_type == 1 { "rsa" } else { "ec" });
                    track_attest_key_material(caller_uid, &alias, &material_id(material));
                    track_attest_signer_state(
                        caller_uid,
                        &alias,
                        TrackedAttestSignerState {
                            signer_cert: cert,
                            signer_key: privkey,
                            algorithm: Some(if key_type == 1 { "rsa".to_string() } else { "ec".to_string() }),
                        },
                    );
                    info!(
                        "[KEYSTORE_COMPAT] Tracked software ATTEST_KEY for uid={:?}, alias={}",
                        caller_uid, alias
                    );
                }
            }

            info!(
                "[KEYSTORE_COMPAT] Minted in-process software key for uid={:?}, alg={}",
                caller_uid, if key_type == 1 { "rsa" } else { "ec" }
            );

            Ok(Some(KeyCreationResult {
                keyBlob: marked_blob,
                keyCharacteristics: vec![],
                certificateChain: full_chain,
            }))
        }
        Err(e) => {
            warn!("[KEYSTORE_COMPAT] Software key generation failed: {:?}", e);
            Ok(None)
        }
    }
}

pub(crate) fn should_prefer_local_attest_key_flow_for_uid(
    caller_uid: AppUid,
    creation_params: &[KeyParameter],
    attest_key_descriptor_present: bool,
) -> bool {
    if !is_attest_key_request(creation_params) || attest_key_descriptor_present {
        return false;
    }

    let cfg = match load_config_for_user(caller_uid.owning_user()) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(
                "tee soft debug: failed to load config while deciding local attest-key flow for uid {:?}: {:?}",
                caller_uid, e
            );
            return false;
        }
    };

    if !cfg.enabled || cfg.target_packages.is_empty() {
        return false;
    }

    let uid_packages = match package_names_for_uid(caller_uid) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "tee soft debug: failed to query packages while deciding local attest-key flow for uid {:?}: {:?}",
                caller_uid, e
            );
            return false;
        }
    };

    uid_packages.iter().any(|pkg| cfg.target_packages.contains_key(pkg))
}

fn track_attest_key_algorithm(uid: AppUid, alias: &str, algorithm: &str) {
    let Ok(mut map) = TRACKED_ATTEST_KEY_ALGORITHM.lock() else {
        warn!("tee soft debug: failed to lock tracked-attest-key algorithm map");
        return;
    };
    map.insert(make_uid_alias_key(uid, alias), algorithm.to_string());
}

fn get_tracked_attest_key_algorithm(uid: AppUid, alias: &str) -> Option<String> {
    let Ok(map) = TRACKED_ATTEST_KEY_ALGORITHM.lock() else {
        warn!("tee soft debug: failed to lock tracked-attest-key algorithm map for lookup");
        return None;
    };
    map.get(&make_uid_alias_key(uid, alias)).cloned()
}

fn track_attest_key_material(uid: AppUid, alias: &str, material_id: &str) {
    let Ok(mut map) = TRACKED_ATTEST_KEY_MATERIAL.lock() else {
        warn!("tee soft debug: failed to lock tracked-attest-key material map");
        return;
    };
    map.insert(make_uid_alias_key(uid, alias), material_id.to_string());
}

fn get_tracked_attest_key_material(uid: AppUid, alias: &str) -> Option<String> {
    let Ok(map) = TRACKED_ATTEST_KEY_MATERIAL.lock() else {
        warn!("tee soft debug: failed to lock tracked-attest-key material map for lookup");
        return None;
    };
    map.get(&make_uid_alias_key(uid, alias)).cloned()
}

fn track_attest_signer_state(uid: AppUid, alias: &str, state: TrackedAttestSignerState) {
    let Ok(mut map) = TRACKED_ATTEST_SIGNERS.lock() else {
        warn!("tee soft debug: failed to lock tracked-attest signer map");
        return;
    };
    map.insert(make_uid_alias_key(uid, alias), state);
}

fn get_tracked_attest_signer_state(uid: AppUid, alias: &str) -> Option<TrackedAttestSignerState> {
    let Ok(map) = TRACKED_ATTEST_SIGNERS.lock() else {
        warn!("tee soft debug: failed to lock tracked-attest signer map for lookup");
        return None;
    };
    map.get(&make_uid_alias_key(uid, alias)).cloned()
}

fn signer_state_from_material(material: &KeyboxMaterial) -> Option<TrackedAttestSignerState> {
    let (Some(signer_cert), Some(signer_key)) = (material.certs.first(), material.signing_key.as_ref()) else {
        return None;
    };
    Some(TrackedAttestSignerState {
        signer_cert: signer_cert.clone(),
        signer_key: signer_key.clone(),
        algorithm: material.algorithm.clone(),
    })
}

fn load_or_init_tracked_attest_signer_state(
    uid: AppUid,
    alias: &str,
    cfg: &CompatAttestConfig,
) -> Option<TrackedAttestSignerState> {
    if let Some(state) = get_tracked_attest_signer_state(uid, alias) {
        return Some(state);
    }
    if cfg.keybox_path.trim().is_empty() {
        return None;
    }

    let keybox_path = Path::new(cfg.keybox_path.trim());
    let materials = match load_keybox_material(keybox_path) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "tee soft debug: failed to load keybox while lazily initializing tracked signer state: {}: {:?}",
                keybox_path.display(),
                e
            );
            return None;
        }
    };

    let tracked_material = get_tracked_attest_key_material(uid, alias);
    let tracked_family = get_tracked_attest_key_algorithm(uid, alias)
        .as_deref()
        .and_then(|algo| normalize_algorithm_family(Some(algo)));

    let selected = tracked_material
        .as_deref()
        .and_then(|mid| materials.iter().find(|m| material_id(m) == mid))
        .and_then(signer_state_from_material)
        .or_else(|| {
            tracked_family.and_then(|family| {
                materials
                    .iter()
                    .filter(|m| {
                        normalize_algorithm_family(m.algorithm.as_deref()) == Some(family)
                    })
                    .find_map(signer_state_from_material)
            })
        })
        .or_else(|| {
            materials
                .iter()
                .filter(|m| normalize_algorithm_family(m.algorithm.as_deref()) == Some("rsa"))
                .find_map(signer_state_from_material)
        })
        .or_else(|| materials.iter().find_map(signer_state_from_material));

    if let Some(state) = selected {
        track_attest_signer_state(uid, alias, state.clone());
        return Some(state);
    }
    None
}

fn package_names_for_uid(uid: AppUid) -> Result<Vec<String>> {
    let pm: Strong<dyn IPackageManagerNative> =
        binder::get_interface("package_native").context("connect package_native")?;

    let pkg_infos = pm
        .getPackageInfoWithSigningInfoForUid(uid.0 as i32)
        .context("get package info for uid")?
        .unwrap_or_default();

    let mut names = Vec::new();
    for pkg_info in pkg_infos.into_iter().flatten() {
        if !pkg_info.packageName.is_empty() {
            names.push(pkg_info.packageName);
        }
    }
    Ok(names)
}

fn upsert_integer_key_param(params: &mut Vec<KeyParameter>, tag: Tag, value: i32) {
    if let Some(existing) = params.iter_mut().find(|p| p.tag == tag) {
        existing.value = KeyParameterValue::Integer(value);
    } else {
        params.push(KeyParameter { tag, value: KeyParameterValue::Integer(value) });
    }
}

fn remove_key_param(params: &mut Vec<KeyParameter>, tag: Tag) {
    params.retain(|p| p.tag != tag);
}

pub(crate) fn maybe_sync_patchlevel_authorizations_for_uid(
    caller_uid: AppUid,
    creation_result: &KeyCreationResult,
    key_params_for_metadata: &mut Vec<KeyParameter>,
) {
    let user = caller_uid.owning_user();
    let cfg = match load_config_for_user(user) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(
                "tee soft debug: failed to load config for patchlevel authorization sync, user {:?}: {:?}",
                user, e
            );
            return;
        }
    };
    if !cfg.enabled || cfg.target_packages.is_empty() {
        return;
    }

    let uid_packages = match package_names_for_uid(caller_uid) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "tee soft debug: failed to query packages for patchlevel authorization sync, uid {:?}: {:?}",
                caller_uid, e
            );
            return;
        }
    };
    let matched = uid_packages.iter().any(|pkg| cfg.target_packages.contains_key(pkg));
    if !matched {
        return;
    }

    let Some(leaf) = creation_result.certificateChain.first() else {
        return;
    };
    let (os_patchlevel, vendor_patchlevel, boot_patchlevel) =
        extract_attestation_patchlevels(&leaf.encodedCertificate);
    if os_patchlevel.is_none() && vendor_patchlevel.is_none() && boot_patchlevel.is_none() {
        warn!(
            "tee soft debug: patchlevel authorization sync skipped; attestation patchlevels unavailable for uid {:?}",
            caller_uid
        );
        return;
    }

    match os_patchlevel {
        Some(v) => upsert_integer_key_param(key_params_for_metadata, Tag::OS_PATCHLEVEL, v),
        None => remove_key_param(key_params_for_metadata, Tag::OS_PATCHLEVEL),
    }
    match vendor_patchlevel {
        Some(v) => upsert_integer_key_param(key_params_for_metadata, Tag::VENDOR_PATCHLEVEL, v),
        None => remove_key_param(key_params_for_metadata, Tag::VENDOR_PATCHLEVEL),
    }
    match boot_patchlevel {
        Some(v) => upsert_integer_key_param(key_params_for_metadata, Tag::BOOT_PATCHLEVEL, v),
        None => remove_key_param(key_params_for_metadata, Tag::BOOT_PATCHLEVEL),
    }

    info!(
        "tee soft debug: synchronized metadata patchlevel authorizations for uid {:?}, packages {:?}: os={:?}, vendor={:?}, boot={:?}",
        caller_uid, uid_packages, os_patchlevel, vendor_patchlevel, boot_patchlevel
    );
}

fn extract_tag_values<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let start_tag = format!("<{tag}");
    let end_tag = format!("</{tag}>");

    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(start_rel) = xml[pos..].find(&start_tag) {
        let start = pos + start_rel;
        // Ensure we match the exact tag boundary (e.g. "<Certificate ...>" or "<Certificate>"),
        // not a superset tag like "<CertificateChain>".
        let after = xml[start + start_tag.len()..].chars().next();
        if !matches!(after, Some('>') | Some(' ') | Some('\n') | Some('\t') | Some('\r')) {
            pos = start + start_tag.len();
            continue;
        }
        let Some(gt_rel) = xml[start..].find('>') else {
            break;
        };
        let body_start = start + gt_rel + 1;
        let Some(end_rel) = xml[body_start..].find(&end_tag) else {
            break;
        };
        let body_end = body_start + end_rel;
        out.push(&xml[body_start..body_end]);
        pos = body_end + end_tag.len();
    }

    out
}

fn pem_or_base64_to_der(raw: &str) -> Option<Vec<u8>> {
    let cleaned = strip_xml_comments(raw);
    let mut payload = cleaned
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace(['\r', '\n', '\t', ' '], "");

    payload = payload.trim().to_string();
    if payload.is_empty() {
        return None;
    }

    STANDARD.decode(payload.as_bytes()).ok()
}

fn parse_private_key_material(raw: &str) -> Option<Vec<u8>> {
    let cleaned = strip_xml_comments(raw);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.contains("-----BEGIN") {
        let normalized = trimmed
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        return Some(normalized.into_bytes());
    }

    let payload = trimmed.replace(['\r', '\n', '\t', ' '], "");
    if payload.is_empty() {
        return None;
    }
    STANDARD.decode(payload.as_bytes()).ok()
}

fn strip_xml_comments(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut pos = 0usize;
    while let Some(start_rel) = raw[pos..].find("<!--") {
        let start = pos + start_rel;
        out.push_str(&raw[pos..start]);
        let after_start = start + 4;
        if let Some(end_rel) = raw[after_start..].find("-->") {
            pos = after_start + end_rel + 3;
        } else {
            // Malformed comment tail: drop the rest to avoid poisoning PEM/base64 payload.
            pos = raw.len();
        }
    }
    if pos < raw.len() {
        out.push_str(&raw[pos..]);
    }
    out
}

fn extract_key_blocks(xml: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut pos = 0usize;
    while let Some(start_rel) = xml[pos..].find("<Key") {
        let start = pos + start_rel;
        let after = xml[start + 4..].chars().next();
        if !matches!(after, Some('>') | Some(' ') | Some('\n') | Some('\t') | Some('\r')) {
            pos = start + 4;
            continue;
        }
        let Some(end_rel) = xml[start..].find("</Key>") else {
            break;
        };
        let end = start + end_rel + "</Key>".len();
        blocks.push(&xml[start..end]);
        pos = end;
    }
    blocks
}

fn parse_key_algorithm(block: &str) -> Option<String> {
    let head_end = block.find('>')?;
    let head = &block[..head_end];
    let key = "algorithm=\"";
    let start = head.find(key)? + key.len();
    let remain = &head[start..];
    let end = remain.find('"')?;
    let value = remain[..end].trim();
    if value.is_empty() { None } else { Some(value.to_ascii_lowercase()) }
}

fn normalize_algorithm_family(algorithm: Option<&str>) -> Option<&'static str> {
    let algo = algorithm?;
    let lower = algo.to_ascii_lowercase();
    if lower.contains("rsa") {
        Some("rsa")
    } else if lower.contains("ec") || lower.contains("ecdsa") {
        Some("ec")
    } else {
        None
    }
}

fn parse_keybox_material_from_xml(xml: &str) -> Result<Vec<KeyboxMaterial>> {
    let key_blocks = extract_key_blocks(xml);
    if key_blocks.is_empty() {
        anyhow::bail!("no <Key> entries in keybox xml");
    }

    let mut materials = Vec::new();
    for block in key_blocks {
        let mut certs = Vec::new();
        for cert_text in extract_tag_values(block, "Certificate") {
            if let Some(der) = pem_or_base64_to_der(cert_text) {
                certs.push(der);
            }
        }
        if certs.is_empty() {
            continue;
        }

        let signing_key = extract_tag_values(block, "PrivateKey")
            .into_iter()
            .find_map(parse_private_key_material);
        let mut algorithm = parse_key_algorithm(block);
        let derived_family = certs
            .first()
            .and_then(|cert| certificate_public_key_family(cert))
            .map(|family| family.to_string());
        match (normalize_algorithm_family(algorithm.as_deref()), derived_family.as_deref()) {
            (Some(parsed), Some(derived)) if parsed != derived => {
                warn!(
                    "tee soft debug: keybox algorithm tag mismatch (tag={:?}, derived_from_cert={}); overriding with derived family",
                    algorithm,
                    derived
                );
                algorithm = Some(derived.to_string());
            }
            (None, Some(derived)) => {
                algorithm = Some(derived.to_string());
            }
            _ => {}
        }
        materials.push(KeyboxMaterial { certs, signing_key, algorithm });
    }

    if materials.is_empty() {
        anyhow::bail!("no usable cert chains in keybox xml");
    }
    Ok(materials)
}

fn pick_plain_chain(materials: &[KeyboxMaterial]) -> Option<(Vec<Vec<u8>>, Option<String>)> {
    let first = materials.first()?;
    Some((first.certs.clone(), first.algorithm.clone()))
}

fn try_resign_with_material(
    original_leaf: &[u8],
    material: &KeyboxMaterial,
) -> Option<Vec<Vec<u8>>> {
    let signing_key = material.signing_key.as_ref()?;
    let signing_cert = material.certs.first()?;
    let resigned_leaf = resign_leaf_certificate(original_leaf, signing_cert, signing_key).ok()?;
    let mut out = material.certs.clone();
    out.insert(0, resigned_leaf);
    Some(out)
}

fn material_id(material: &KeyboxMaterial) -> String {
    let algorithm = material.algorithm.as_deref().unwrap_or("unknown");
    let Some(first_cert) = material.certs.first() else {
        return format!("algo={algorithm}|empty");
    };
    let subject = parse_subject_from_certificate(first_cert)
        .map(|v| hex_prefix(&v, 12))
        .unwrap_or_else(|_| "subject-parse-failed".to_string());
    let issuer = parse_issuer_from_certificate(first_cert)
        .map(|v| hex_prefix(&v, 12))
        .unwrap_or_else(|_| "issuer-parse-failed".to_string());
    format!("algo={algorithm}|subject={subject}|issuer={issuer}|len={}", first_cert.len())
}

fn validate_chain_for_keyattestation(chain: &[Vec<u8>]) -> Result<(), usize> {
    if chain.is_empty() {
        return Err(0);
    }

    for (i, cert) in chain.iter().enumerate() {
        let outer_sig_family = certificate_signature_key_family(cert);
        let tbs_sig_family = certificate_tbs_signature_key_family(cert);
        if outer_sig_family.is_some()
            && tbs_sig_family.is_some()
            && outer_sig_family != tbs_sig_family
        {
            warn!(
                "tee soft debug: cert self inconsistency at step {}, outer_sig_family={:?}, tbs_sig_family={:?}",
                i,
                outer_sig_family,
                tbs_sig_family
            );
            return Err(i);
        }
    }

    if chain.len() >= 2 {
        for i in 0..(chain.len() - 1) {
            let child_sig_family = certificate_signature_key_family(&chain[i]);
            let parent_pub_family = certificate_public_key_family(&chain[i + 1]);
            if child_sig_family.is_some()
                && parent_pub_family.is_some()
                && child_sig_family != parent_pub_family
            {
                warn!(
                    "tee soft debug: chain family mismatch at step {}, child_sig_family={:?}, parent_pub_family={:?}",
                    i,
                    child_sig_family,
                    parent_pub_family
                );
                return Err(i);
            }
            if !signature_family_compatible(&chain[i], &chain[i + 1]) {
                return Err(i);
            }
            if !verify_certificate_signed_by(&chain[i], &chain[i + 1]) {
                return Err(i);
            }
        }
    }

    // KeyAttestation verifies the last cert with its own public key (self-signed root).
    let last = chain.len() - 1;
    let root_sig_family = certificate_signature_key_family(&chain[last]);
    let root_pub_family = certificate_public_key_family(&chain[last]);
    if root_sig_family.is_some() && root_pub_family.is_some() && root_sig_family != root_pub_family
    {
        warn!(
            "tee soft debug: root family mismatch at step {}, root_sig_family={:?}, root_pub_family={:?}",
            last,
            root_sig_family,
            root_pub_family
        );
        return Err(last);
    }
    if !verify_certificate_signed_by(&chain[last], &chain[last]) {
        return Err(last);
    }

    Ok(())
}

fn signature_family_compatible(cert: &[u8], parent: &[u8]) -> bool {
    let cert_sig = certificate_signature_key_family(cert);
    let parent_pub = certificate_public_key_family(parent);
    if cert_sig.is_some() && parent_pub.is_some() && cert_sig != parent_pub {
        return false;
    }
    true
}

#[derive(Clone)]
struct CertNamePair {
    subject: Vec<u8>,
    issuer: Vec<u8>,
}

fn parse_name_pairs(chain: &[Vec<u8>]) -> Option<Vec<CertNamePair>> {
    let mut out = Vec::with_capacity(chain.len());
    for cert in chain {
        let subject = parse_subject_from_certificate(cert).ok()?;
        let issuer = parse_issuer_from_certificate(cert).ok()?;
        out.push(CertNamePair { subject, issuer });
    }
    Some(out)
}

fn hex_prefix(bytes: &[u8], max_len: usize) -> String {
    let mut out = String::new();
    for b in bytes.iter().take(max_len) {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn chain_name_summary(chain: &[Vec<u8>]) -> Vec<String> {
    let Some(names) = parse_name_pairs(chain) else {
        return vec!["name-parse-failed".to_string()];
    };
    names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            format!(
                "#{i}:subject={},issuer={},self_issued={}",
                hex_prefix(&n.subject, 10),
                hex_prefix(&n.issuer, 10),
                n.subject == n.issuer
            )
        })
        .collect()
}

fn reorder_chain_like_keyattestation(chain: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if chain.len() < 2 {
        return chain.to_vec();
    }

    let Some(names) = parse_name_pairs(chain) else {
        // If name parsing fails, avoid mutating order unexpectedly.
        return chain.to_vec();
    };

    // Match KeyAttestation's first pass behavior.
    let mut okay = true;
    let mut issuer = names[0].issuer.as_slice();
    for name in &names {
        if issuer == name.subject.as_slice() {
            issuer = name.subject.as_slice();
        } else {
            okay = false;
            break;
        }
    }
    if okay {
        return chain.to_vec();
    }

    let mut new_indices = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let found = names.iter().enumerate().any(|(j, other)| j != i && other.issuer == name.subject);
        if !found {
            new_indices.push(i);
        }
    }
    if new_indices.len() != 1 {
        return chain.to_vec();
    }

    let mut old_indices: Vec<usize> = (0..chain.len()).collect();
    old_indices.retain(|idx| *idx != new_indices[0]);

    let mut i = 0usize;
    while i < new_indices.len() {
        let issuer_name = names[new_indices[i]].issuer.as_slice();
        if let Some((pos, _)) = old_indices
            .iter()
            .enumerate()
            .find(|(_, idx)| names[**idx].subject.as_slice() == issuer_name)
        {
            let next_idx = old_indices.remove(pos);
            new_indices.push(next_idx);
        }
        i += 1;
    }

    if !old_indices.is_empty() {
        return chain.to_vec();
    }

    new_indices.into_iter().map(|idx| chain[idx].clone()).collect()
}

fn validate_chain_in_keyattestation_view(chain: &[Vec<u8>]) -> Result<(), usize> {
    let sorted = reorder_chain_like_keyattestation(chain);
    validate_chain_for_keyattestation(&sorted)
}

fn keyattestation_step_summary(chain: &[Vec<u8>]) -> Vec<String> {
    let sorted = reorder_chain_like_keyattestation(chain);
    if sorted.is_empty() {
        return vec!["empty-chain".to_string()];
    }

    let mut parent_idx = sorted.len() - 1;
    let mut summary = Vec::new();
    for i in (0..sorted.len()).rev() {
        let ok = if signature_family_compatible(&sorted[i], &sorted[parent_idx]) {
            verify_certificate_signed_by(&sorted[i], &sorted[parent_idx])
        } else {
            false
        };
        summary.push(format!(
            "step cert#{i} by parent#{parent_idx}: ok={}, cert_sig={:?}, parent_pub={:?}",
            ok,
            certificate_signature_key_family(&sorted[i]),
            certificate_public_key_family(&sorted[parent_idx])
        ));
        if i != sorted.len() - 1 {
            parent_idx = i;
        }
    }
    summary
}

fn linearize_chain_by_signature(chain: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if chain.len() < 2 {
        return chain.to_vec();
    }

    let mut out = Vec::with_capacity(chain.len());
    out.push(chain[0].clone());
    let mut used = vec![false; chain.len()];
    used[0] = true;
    let mut current = 0usize;

    loop {
        let child = &chain[current];
        let child_issuer = parse_issuer_from_certificate(child).ok();
        let mut candidates: Vec<usize> = (0..chain.len())
            .filter(|idx| !used[*idx])
            .filter(|idx| {
                if let Some(issuer) = child_issuer.as_ref() {
                    parse_subject_from_certificate(&chain[*idx]).ok().as_ref() == Some(issuer)
                } else {
                    true
                }
            })
            .collect();
        if candidates.is_empty() {
            break;
        }

        if child_issuer.is_none() {
            let child_sig_family = certificate_signature_key_family(child);
            candidates.sort_by_key(|idx| {
                let parent_pub_family = certificate_public_key_family(&chain[*idx]);
                if child_sig_family.is_some() && child_sig_family == parent_pub_family {
                    0usize
                } else {
                    1usize
                }
            });
        }

        let Some(parent_idx) = candidates
            .into_iter()
            .find(|idx| {
                signature_family_compatible(child, &chain[*idx])
                    && verify_certificate_signed_by(child, &chain[*idx])
            })
        else {
            break;
        };
        used[parent_idx] = true;
        out.push(chain[parent_idx].clone());
        current = parent_idx;

        if signature_family_compatible(&chain[parent_idx], &chain[parent_idx])
            && verify_certificate_signed_by(&chain[parent_idx], &chain[parent_idx])
        {
            break;
        }
    }

    if out.len() >= 2 && validate_chain_for_keyattestation(&out).is_ok() {
        out
    } else {
        chain.to_vec()
    }
}

fn chain_family_summary(chain: &[Vec<u8>]) -> Vec<String> {
    chain
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            let sig = certificate_signature_key_family(cert);
            let tbs_sig = certificate_tbs_signature_key_family(cert);
            let pubk = certificate_public_key_family(cert);
            format!("#{i}:sig={sig:?},tbs_sig={tbs_sig:?},pub={pubk:?}")
        })
        .collect()
}

fn chain_transition_score(chain: &[Vec<u8>]) -> usize {
    let families: Vec<Option<&'static str>> =
        chain.iter().map(|cert| certificate_signature_key_family(cert)).collect();
    let mut transitions = 0usize;
    let mut unknowns = 0usize;
    for f in &families {
        if f.is_none() {
            unknowns += 1;
        }
    }
    for pair in families.windows(2) {
        if pair[0].is_some() && pair[1].is_some() && pair[0] != pair[1] {
            transitions += 1;
        }
    }
    transitions * 10 + unknowns
}

fn select_best_chain(
    original_leaf: &[u8],
    materials: &[KeyboxMaterial],
    forced_algorithm_family: Option<&'static str>,
) -> Option<(Vec<Vec<u8>>, Option<String>, Option<String>)> {
    let preferred_family = forced_algorithm_family.or_else(|| certificate_signature_key_family(original_leaf));
    if preferred_family.is_none() {
        warn!("tee soft debug: unable to derive original leaf signature key family");
    }

    let mut best_match_chain: Option<Vec<Vec<u8>>> = None;
    let mut best_match_algorithm: Option<String> = None;
    let mut best_match_material_id: Option<String> = None;
    let mut best_match_score: Option<usize> = None;
    let mut best_other_chain: Option<Vec<Vec<u8>>> = None;
    let mut best_other_algorithm: Option<String> = None;
    let mut best_other_material_id: Option<String> = None;
    let mut best_other_score: Option<usize> = None;

    let mut consider_candidate =
        |chain: Vec<Vec<u8>>, algorithm: Option<String>, material_id: Option<String>| {
        let score = chain_transition_score(&chain);
        let algo_family = normalize_algorithm_family(algorithm.as_deref());
        let family_match = preferred_family.is_some() && preferred_family == algo_family;
        if family_match {
            let replace = match best_match_score {
                None => true,
                Some(current) => score < current,
            };
            if replace {
                best_match_score = Some(score);
                best_match_algorithm = algorithm;
                best_match_material_id = material_id;
                best_match_chain = Some(chain);
            }
        } else {
            let replace = match best_other_score {
                None => true,
                Some(current) => score < current,
            };
            if replace {
                best_other_score = Some(score);
                best_other_algorithm = algorithm;
                best_other_material_id = material_id;
                best_other_chain = Some(chain);
            }
        }
    };

    let mut visit_material = |material: &KeyboxMaterial| {
        let mut accepted = false;
        let mid = material_id(material);
        if let Some(chain) = try_resign_with_material(original_leaf, material) {
            match validate_chain_for_keyattestation(&chain) {
                Ok(()) => {
                    match validate_chain_in_keyattestation_view(&chain) {
                        Ok(()) => {
                            accepted = true;
                            consider_candidate(chain, material.algorithm.clone(), Some(mid.clone()))
                        }
                        Err(step) => {
                            warn!(
                                "tee soft debug: re-sign candidate failed in keyattestation sort/view at step {}, key_algorithm={:?}",
                                step,
                                material.algorithm
                            );
                        }
                    }
                }
                Err(step) => {
                    warn!(
                        "tee soft debug: re-sign candidate chain validation failed at step {}, key_algorithm={:?}",
                        step,
                        material.algorithm
                    );
                }
            }
        }
        if material.signing_key.is_some() && !accepted {
            warn!(
                "tee soft debug: re-sign candidate rejected, key_algorithm={:?}",
                material.algorithm
            );
        }
    };

    // Prefer candidates that can successfully re-sign and self-verify in native layer.
    let mut has_signing_key_candidate = false;
    for material in materials.iter().filter(|m| m.signing_key.is_some()) {
        has_signing_key_candidate = true;
        if normalize_algorithm_family(material.algorithm.as_deref()) == preferred_family {
            visit_material(material);
        }
    }

    for material in materials.iter().filter(|m| m.signing_key.is_some()) {
        let family = normalize_algorithm_family(material.algorithm.as_deref());
        if family == preferred_family {
            continue;
        }
        visit_material(material);
    }
    // If no key entry provides a signing key, fall back to plain keybox chain.
    if !has_signing_key_candidate {
        if let Some((chain, algorithm)) = pick_plain_chain(materials) {
            match validate_chain_for_keyattestation(&chain) {
                Ok(()) => match validate_chain_in_keyattestation_view(&chain) {
                    Ok(()) => {
                        let mid = materials.first().map(material_id);
                        consider_candidate(chain, algorithm, mid)
                    }
                    Err(step) => {
                        warn!(
                            "tee soft debug: plain keybox chain failed in keyattestation sort/view at step {}, key_algorithm={:?}",
                            step,
                            algorithm
                        );
                    }
                },
                Err(step) => {
                    warn!(
                        "tee soft debug: plain keybox chain validation failed at step {}, key_algorithm={:?}",
                        step,
                        algorithm
                    );
                }
            }
        }
    }
    if let Some(chain) = best_match_chain {
        info!(
            "tee soft debug: selected candidate chain score={}, family_match_with_original=true",
            best_match_score.unwrap_or_default()
        );
        return Some((chain, best_match_algorithm, best_match_material_id));
    }

    if let Some(chain) = best_other_chain {
        info!(
            "tee soft debug: selected candidate chain score={}, family_match_with_original=false",
            best_other_score.unwrap_or_default()
        );
        return Some((chain, best_other_algorithm, best_other_material_id));
    }

    None
}

fn parse_keybox_material_legacy(xml: &str) -> Result<KeyboxMaterial> {
    let mut certs = Vec::new();
    for cert_text in extract_tag_values(xml, "Certificate") {
        if let Some(der) = pem_or_base64_to_der(cert_text) {
            certs.push(der);
        }
    }

    if certs.is_empty() {
        anyhow::bail!("no decodable <Certificate> entries in keybox xml");
    }

    let signing_key = extract_tag_values(xml, "PrivateKey")
        .into_iter()
        .find_map(parse_private_key_material);

    let algorithm = certs
        .first()
        .and_then(|cert| certificate_public_key_family(cert))
        .map(|family| family.to_string());
    Ok(KeyboxMaterial { certs, signing_key, algorithm })
}

fn load_keybox_material(path: &Path) -> Result<Vec<KeyboxMaterial>> {
    let xml = fs::read_to_string(path).with_context(|| format!("read keybox xml: {}", path.display()))?;
    parse_keybox_material_from_xml(&xml).or_else(|_| parse_keybox_material_legacy(&xml).map(|m| vec![m]))
}

pub(crate) fn maybe_override_certificate_chain_for_uid(
    caller_uid: AppUid,
    creation_params: &[KeyParameter],
    has_external_attestation_key: bool,
    uses_tracked_attest_key: bool,
    current_key_alias: Option<&str>,
    attest_key_descriptor: Option<&KeyDescriptor>,
    creation_result: &mut KeyCreationResult,
) {
    let user = caller_uid.owning_user();
    let cfg = match load_config_for_user(user) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("tee soft debug: failed to load config for user {:?}: {:?}", user, e);
            return;
        }
    };

    if !cfg.enabled || cfg.target_packages.is_empty() {
        return;
    }

    let uid_packages = match package_names_for_uid(caller_uid) {
        Ok(v) => v,
        Err(e) => {
            warn!("tee soft debug: failed to query packages for uid {:?}: {:?}", caller_uid, e);
            return;
        }
    };

    let matched = uid_packages.iter().any(|pkg| cfg.target_packages.contains_key(pkg));
    if !matched {
        return;
    }

    if has_external_attestation_key && !uses_tracked_attest_key {
        info!(
            "tee soft debug: skip override because key generation used an external attestation key, uid={:?}",
            caller_uid
        );
        return;
    }

    if has_external_attestation_key && uses_tracked_attest_key {
        let alias = attest_key_descriptor.and_then(|d| normalize_alias(d.alias.as_deref()));
        let Some(alias) = alias else {
            info!(
                "tee soft debug: external attestation key tracked but alias unavailable; skip override for uid={:?}",
                caller_uid
            );
            return;
        };
        let Some(state) = load_or_init_tracked_attest_signer_state(caller_uid, &alias, &cfg) else {
            info!(
                "tee soft debug: external attestation key tracked but signer state missing for alias={}; skip override for uid={:?}",
                alias, caller_uid
            );
            return;
        };
        if creation_result.certificateChain.is_empty() {
            return;
        }
        let original_leaf = creation_result.certificateChain[0].encodedCertificate.clone();
        let resigned_leaf = match resign_leaf_certificate(&original_leaf, &state.signer_cert, &state.signer_key)
        {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "tee soft debug: tracked external attest signer failed to resign leaf for uid={:?}, alias={}, algorithm={:?}: {:?}",
                    caller_uid, alias, state.algorithm, e
                );
                return;
            }
        };
        if !verify_certificate_signed_by(&resigned_leaf, &state.signer_cert) {
            warn!(
                "tee soft debug: tracked external attest signer produced unverifiable leaf for uid={:?}, alias={}; skip override",
                caller_uid, alias
            );
            return;
        }
        creation_result.certificateChain = vec![Certificate { encodedCertificate: resigned_leaf }];
        info!(
            "tee soft debug: external attestation key tracked; replaced leaf only using tracked signer for uid={:?}, alias={}, algorithm={:?}",
            caller_uid, alias, state.algorithm
        );
        return;
    }

    let has_original_chain = !creation_result.certificateChain.is_empty();
    let is_attest_key = is_attest_key_request(creation_params);

    let target_mode = get_target_mode_for_packages(&cfg, &uid_packages).unwrap_or(cfg.mode);
    let action = decide_action_for_mode(cfg.enabled, target_mode, is_attest_key, has_original_chain);
    match action {
        CompatAttestAction::Skip => return,
        CompatAttestAction::GenerateSoftwareChain => {
            info!(
                "tee soft debug: software generation action requested (mode={:?}, is_attest_key={}, uid={:?}); continue with patch flow after generation",
                target_mode, is_attest_key, caller_uid
            );
        }
        CompatAttestAction::PatchExistingChain => {}
    }

    if cfg.keybox_path.trim().is_empty() {
        info!(
            "tee soft debug: enabled and package matched, but no keybox configured; skip override for uid {:?}",
            caller_uid
        );
        return;
    }

    let keybox_path = Path::new(cfg.keybox_path.trim());
    let materials = match load_keybox_material(keybox_path) {
        Ok(materials) => materials,
        Err(e) => {
            warn!(
                "tee soft debug: failed to parse keybox {}: {:?}",
                keybox_path.display(),
                e
            );
            return;
        }
    };

    let original_leaf = creation_result.certificateChain[0].encodedCertificate.clone();
    let tracked_forced_family = attest_key_descriptor
        .and_then(|d| normalize_alias(d.alias.as_deref()))
        .and_then(|alias| get_tracked_attest_key_algorithm(caller_uid, &alias))
        .as_deref()
        .and_then(|algo| normalize_algorithm_family(Some(algo)));
    let tracked_forced_material = attest_key_descriptor
        .and_then(|d| normalize_alias(d.alias.as_deref()))
        .and_then(|alias| get_tracked_attest_key_material(caller_uid, &alias));
    let mut selected = select_best_chain(&original_leaf, &materials, tracked_forced_family);
    if let Some(forced_mid) = tracked_forced_material.as_deref() {
        let pinned_materials: Vec<KeyboxMaterial> = materials
            .iter()
            .filter(|m| material_id(m) == forced_mid)
            .cloned()
            .collect();
        if !pinned_materials.is_empty() {
            let pinned_selected = select_best_chain(&original_leaf, &pinned_materials, tracked_forced_family);
            if pinned_selected.is_some() {
                selected = pinned_selected;
            }
        }
    }
    if uses_tracked_attest_key {
        if let Some((current_chain, _, _)) = selected.as_ref() {
            if chain_transition_score(current_chain) > 0 {
                if let Some(rsa_selected) = select_best_chain(&original_leaf, &materials, Some("rsa")) {
                    info!(
                        "tee soft debug: tracked external attest-key path picked mixed-family chain; switching preference to rsa-family candidate for compatibility"
                    );
                    selected = Some(rsa_selected);
                }
            }
        }
    }
    if is_attest_key {
        if let Some((current_chain, _, _)) = selected.as_ref() {
            if chain_transition_score(current_chain) > 0 {
                if let Some(rsa_selected) = select_best_chain(&original_leaf, &materials, Some("rsa")) {
                    info!(
                        "tee soft debug: ATTEST_KEY path picked mixed-family chain; switching preference to rsa-family candidate for persistent-key compatibility"
                    );
                    selected = Some(rsa_selected);
                }
            }
        }
    }
    let Some((output_chain, selected_algorithm, selected_material)) = selected
    else {
        warn!("tee soft debug: no usable keybox chain selected for {}", cfg.keybox_path);
        return;
    };

    if is_attest_key {
        let key_type = if selected_algorithm.as_deref() == Some("rsa") { 1 } else { 2 };
        let rsa_size = 2048;
        let challenge = creation_params
            .iter()
            .find(|p| p.tag == Tag::ATTESTATION_CHALLENGE)
            .and_then(|p| match &p.value {
                KeyParameterValue::Blob(b) => Some(b.as_slice()),
                _ => None,
            })
            .unwrap_or(b"attest_challenge");

        if let Some(mid) = selected_material.as_deref() {
            if let Some(material) = materials.iter().find(|m| material_id(m) == mid) {
                if let (Some(signing_cert), Some(signing_key)) =
                    (material.certs.first(), material.signing_key.as_ref())
                {
                    match generate_software_attested_key(
                        key_type,
                        rsa_size,
                        challenge,
                        signing_cert,
                        signing_key,
                        true,
                    ) {
                        Ok((privkey, cert)) => {
                            creation_result.keyBlob = mark_simulated_blob(privkey.clone());
                            let mut full_chain = vec![Certificate { encodedCertificate: cert.clone() }];
                            for c in &material.certs {
                                full_chain.push(Certificate { encodedCertificate: c.clone() });
                            }
                            creation_result.certificateChain = full_chain;

                            if let Some(alias) = normalize_alias(current_key_alias) {
                                track_attest_key_algorithm(caller_uid, &alias, if key_type == 1 { "rsa" } else { "ec" });
                                track_attest_key_material(caller_uid, &alias, mid);
                                track_attest_signer_state(
                                    caller_uid,
                                    &alias,
                                    TrackedAttestSignerState {
                                        signer_cert: cert,
                                        signer_key: privkey,
                                        algorithm: Some(if key_type == 1 { "rsa".to_string() } else { "ec".to_string() }),
                                    },
                                );
                                info!(
                                    "[KEYSTORE_COMPAT] Minted and tracked software ATTEST_KEY for uid={:?}, alias={}, algorithm={}",
                                    caller_uid, alias, if key_type == 1 { "rsa" } else { "ec" }
                                );
                            }
                            return;
                        }
                        Err(e) => {
                            warn!("[KEYSTORE_COMPAT] Failed to mint software ATTEST_KEY: {:?}, falling back to leaf patch", e);
                        }
                    }
                }
            }
        }
    }

    let output_chain = linearize_chain_by_signature(&output_chain);
    let chain_summary = chain_family_summary(&output_chain);
    let chain_name_summary = chain_name_summary(&output_chain);
    let keyattestation_steps = keyattestation_step_summary(&output_chain);
    creation_result.certificateChain = output_chain
        .into_iter()
        .map(|encoded| Certificate { encodedCertificate: encoded })
        .collect();

    let algorithms: Vec<&str> = materials
        .iter()
        .filter_map(|m| m.algorithm.as_deref())
        .collect();
    info!(
        "tee soft debug: replaced attestation chain for uid {:?}, packages {:?}, keybox_path {}, selected_algorithm {:?}, key_algorithms {:?}, chain_summary {:?}, chain_names {:?}, keyattestation_steps {:?}",
        caller_uid,
        uid_packages,
        cfg.keybox_path,
        selected_algorithm,
        algorithms,
        chain_summary,
        chain_name_summary,
        keyattestation_steps
    );
}
