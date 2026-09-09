// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module implements safe wrappers for some crypto operations required by
//! Keystore 2.0.

mod error;
pub mod zvec;
pub use error::Error;
use keystore2_crypto_bindgen::{
    extractAttestationPatchLevels, extractIssuerFromCertificate, extractSubjectFromCertificate,
    hmacSha256, randomBytes,
    AES_gcm_decrypt, AES_gcm_encrypt,
    getCertificatePublicKeyFamily, getCertificateSignatureKeyFamily,
    getCertificateTbsSignatureKeyFamily,
    ECDHComputeKey, ECKEYGenerateKey, ECKEYMarshalPrivateKey, ECKEYParsePrivateKey,
    ECPOINTOct2Point, ECPOINTPoint2Oct, EC_KEY_free, EC_KEY_get0_public_key, EC_POINT_free,
    HKDFExpand, HKDFExtract, PBKDF2, verifyCertificateSignedBy, EC_KEY,
    EC_POINT, EVP_MAX_MD_SIZE,
};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::marker::PhantomData;
pub use zvec::ZVec;

/// Length of the expected initialization vector.
pub const GCM_IV_LENGTH: usize = 12;
/// Length of the expected AEAD TAG.
pub const TAG_LENGTH: usize = 16;
/// Length of an AES 256 key in bytes.
pub const AES_256_KEY_LENGTH: usize = 32;
/// Length of an AES 128 key in bytes.
pub const AES_128_KEY_LENGTH: usize = 16;
/// Length of the expected salt for key from password generation.
pub const SALT_LENGTH: usize = 16;
/// Length of an HMAC-SHA256 tag in bytes.
pub const HMAC_SHA256_LEN: usize = 32;
/// Length of ECDH P-521 output in bytes.
pub const ECDH_P521_OUTPUT_LEN: usize = 66;

/// Older versions of keystore incorrectly truncated ECDH P-521 outputs to the following length.
/// Retain the ability to decrypt keys that were stored in the database using the old method.
pub const LEGACY_TRUNCATED_ECDH_OUTPUT_LEN: usize = 32;

/// Older versions of keystore produced IVs with four extra
/// ignored zero bytes at the end; recognise and trim those.
pub const LEGACY_IV_LENGTH: usize = 16;

/// Generate an AES256 key, essentially 32 random bytes from the underlying
/// boringssl library discretely stuffed into a ZVec.
pub fn generate_aes256_key() -> Result<ZVec, Error> {
    let mut key = ZVec::new(AES_256_KEY_LENGTH)?;
    // Safety: key has the same length as the requested number of random bytes.
    if unsafe { randomBytes(key.as_mut_ptr(), AES_256_KEY_LENGTH) } {
        Ok(key)
    } else {
        Err(Error::RandomNumberGenerationFailed)
    }
}

/// Generate a salt.
pub fn generate_salt() -> Result<Vec<u8>, Error> {
    generate_random_data(SALT_LENGTH)
}

/// Generate random data of the given size.
pub fn generate_random_data(size: usize) -> Result<Vec<u8>, Error> {
    let mut data = vec![0; size];
    // Safety: data has the same length as the requested number of random bytes.
    if unsafe { randomBytes(data.as_mut_ptr(), size) } {
        Ok(data)
    } else {
        Err(Error::RandomNumberGenerationFailed)
    }
}

/// Perform HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let mut tag = vec![0; HMAC_SHA256_LEN];
    // Safety: The first two pairs of arguments must point to const buffers with
    // size given by the second arg of the pair.  The final pair of arguments
    // must point to an output buffer with size given by the second arg of the
    // pair.
    match unsafe {
        hmacSha256(key.as_ptr(), key.len(), msg.as_ptr(), msg.len(), tag.as_mut_ptr(), tag.len())
    } {
        true => Ok(tag),
        false => Err(Error::HmacSha256Failed),
    }
}

/// Uses AES GCM to decipher a message given an initialization vector, aead tag, and key.
/// This function accepts 128 and 256-bit keys and uses AES128 and AES256 respectively based
/// on the key length.
/// This function returns the plaintext message in a ZVec because it is assumed that
/// it contains sensitive information that should be zeroed from memory before its buffer is
/// freed. Input key is taken as a slice for flexibility, but it is recommended that it is held
/// in a ZVec as well.
pub fn aes_gcm_decrypt(data: &[u8], iv: &[u8], tag: &[u8], key: &[u8]) -> Result<ZVec, Error> {
    // Old versions of aes_gcm_encrypt produced 16 byte IVs, but the last four bytes were ignored
    // so trim these to the correct size.
    let iv = match iv.len() {
        GCM_IV_LENGTH => iv,
        LEGACY_IV_LENGTH => &iv[..GCM_IV_LENGTH],
        _ => return Err(Error::InvalidIvLength),
    };
    if tag.len() != TAG_LENGTH {
        return Err(Error::InvalidAeadTagLength);
    }

    match key.len() {
        AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
        _ => return Err(Error::InvalidKeyLength),
    }

    let mut result = ZVec::new(data.len())?;

    // Safety: The first two arguments must point to buffers with a size given by the third
    // argument. We pass the length of the key buffer along with the key.
    // The `iv` buffer must be 12 bytes and the `tag` buffer 16, which we check above.
    match unsafe {
        AES_gcm_decrypt(
            data.as_ptr(),
            result.as_mut_ptr(),
            data.len(),
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
            tag.as_ptr(),
        )
    } {
        true => Ok(result),
        false => Err(Error::DecryptionFailed),
    }
}

/// Uses AES GCM to encrypt a message given a key.
/// This function accepts 128 and 256-bit keys and uses AES128 and AES256 respectively based on
/// the key length. The function generates an initialization vector. The return value is a tuple
/// of `(ciphertext, iv, tag)`.
pub fn aes_gcm_encrypt(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let mut iv = vec![0; GCM_IV_LENGTH];
    // Safety: iv is GCM_IV_LENGTH bytes long.
    if !unsafe { randomBytes(iv.as_mut_ptr(), GCM_IV_LENGTH) } {
        return Err(Error::RandomNumberGenerationFailed);
    }

    match key.len() {
        AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
        _ => return Err(Error::InvalidKeyLength),
    }

    let mut ciphertext: Vec<u8> = vec![0; plaintext.len()];
    let mut tag: Vec<u8> = vec![0; TAG_LENGTH];
    // Safety: The first two arguments must point to buffers with a size given by the third
    // argument. We pass the length of the key buffer along with the key.
    // The `iv` buffer must be 12 bytes and the `tag` buffer 16, which we check above.
    if unsafe {
        AES_gcm_encrypt(
            plaintext.as_ptr(),
            ciphertext.as_mut_ptr(),
            plaintext.len(),
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
            tag.as_mut_ptr(),
        )
    } {
        Ok((ciphertext, iv, tag))
    } else {
        Err(Error::EncryptionFailed)
    }
}

/// A high-entropy synthetic password from which an AES key may be derived.
pub enum Password<'a> {
    /// Borrow an existing byte array
    Ref(&'a [u8]),
    /// Use an owned ZVec to store the key
    Owned(ZVec),
}

impl<'a> From<&'a [u8]> for Password<'a> {
    fn from(pw: &'a [u8]) -> Self {
        Self::Ref(pw)
    }
}

impl<'a> Password<'a> {
    fn get_key(&'a self) -> &'a [u8] {
        match self {
            Self::Ref(b) => b,
            Self::Owned(z) => z,
        }
    }

    /// Derives a key from the given password and salt, using PBKDF2 with 8192 iterations.
    ///
    /// The salt length must be 16 bytes, and the output key length must be 16 or 32 bytes.
    ///
    /// This function exists only for backwards compatibility reasons.  Keystore now receives only
    /// high-entropy synthetic passwords, which do not require key stretching.
    pub fn derive_key_pbkdf2(&self, salt: &[u8], out_len: usize) -> Result<ZVec, Error> {
        if salt.len() != SALT_LENGTH {
            return Err(Error::InvalidSaltLength);
        }
        match out_len {
            AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
            _ => return Err(Error::InvalidKeyLength),
        }

        let pw = self.get_key();
        let mut result = ZVec::new(out_len)?;

        // Safety: We checked that the salt is exactly 16 bytes long. The other pointers are valid,
        // and have matching lengths.
        unsafe {
            PBKDF2(
                result.as_mut_ptr(),
                result.len(),
                pw.as_ptr() as *const std::os::raw::c_char,
                pw.len(),
                salt.as_ptr(),
            )
        };

        Ok(result)
    }

    /// Derives a key from the given high-entropy synthetic password and salt, using HKDF.
    pub fn derive_key_hkdf(&self, salt: &[u8], out_len: usize) -> Result<ZVec, Error> {
        let prk = hkdf_extract(self.get_key(), salt)?;
        let info = [];
        hkdf_expand(out_len, &prk, &info)
    }

    /// Try to make another Password object with the same data.
    pub fn try_clone(&self) -> Result<Password<'static>, Error> {
        Ok(Password::Owned(ZVec::try_from(self.get_key())?))
    }
}

/// Calls the boringssl HKDF_extract function.
pub fn hkdf_extract(secret: &[u8], salt: &[u8]) -> Result<ZVec, Error> {
    let max_size: usize = EVP_MAX_MD_SIZE.try_into().unwrap();
    let mut buf = ZVec::new(max_size)?;
    let mut out_len = 0;
    // Safety: HKDF_extract writes at most EVP_MAX_MD_SIZE bytes.
    // Secret and salt point to valid buffers.
    let result = unsafe {
        HKDFExtract(
            buf.as_mut_ptr(),
            &mut out_len,
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };
    if !result {
        return Err(Error::HKDFExtractFailed);
    }
    // According to the boringssl API, this should never happen.
    if out_len > max_size {
        return Err(Error::HKDFExtractFailed);
    }
    // HKDF_extract may write fewer than the maximum number of bytes, so we
    // truncate the buffer.
    buf.reduce_len(out_len);
    Ok(buf)
}

/// Calls the boringssl HKDF_expand function.
pub fn hkdf_expand(out_len: usize, prk: &[u8], info: &[u8]) -> Result<ZVec, Error> {
    let mut buf = ZVec::new(out_len)?;
    // Safety: HKDF_expand writes out_len bytes to the buffer.
    // prk and info are valid buffers.
    let result = unsafe {
        HKDFExpand(buf.as_mut_ptr(), out_len, prk.as_ptr(), prk.len(), info.as_ptr(), info.len())
    };
    if !result {
        return Err(Error::HKDFExpandFailed);
    }
    Ok(buf)
}

/// A wrapper around the boringssl EC_KEY type that frees it on drop.
pub struct ECKey(*mut EC_KEY);

impl Drop for ECKey {
    fn drop(&mut self) {
        // Safety: We only create ECKey objects for valid EC_KEYs
        // and they are the sole owners of those keys.
        unsafe { EC_KEY_free(self.0) };
    }
}

// Wrappers around the boringssl EC_POINT type.
// The EC_POINT can either be owned (and therefore mutable) or a pointer to an
// EC_POINT owned by someone else (and thus immutable).  The former are freed
// on drop.

/// An owned EC_POINT object.
pub struct OwnedECPoint(*mut EC_POINT);

/// A pointer to an EC_POINT object.
pub struct BorrowedECPoint<'a> {
    data: *const EC_POINT,
    phantom: PhantomData<&'a EC_POINT>,
}

impl OwnedECPoint {
    /// Get the wrapped EC_POINT object.
    pub fn get_point(&self) -> &EC_POINT {
        // Safety: We only create OwnedECPoint objects for valid EC_POINTs.
        unsafe { self.0.as_ref().unwrap() }
    }
}

impl BorrowedECPoint<'_> {
    /// Get the wrapped EC_POINT object.
    pub fn get_point(&self) -> &EC_POINT {
        // Safety: We only create BorrowedECPoint objects for valid EC_POINTs.
        unsafe { self.data.as_ref().unwrap() }
    }
}

impl Drop for OwnedECPoint {
    fn drop(&mut self) {
        // Safety: We only create OwnedECPoint objects for valid
        // EC_POINTs and they are the sole owners of those points.
        unsafe { EC_POINT_free(self.0) };
    }
}

/// Selects how the ECDH P-521 output is used.
#[derive(Clone, Copy)]
pub enum EcdhComputeKeyVersion {
    /// Use only the first 32 bytes of the ECDH P-521 output.  This does not follow cryptographic
    /// best practices.  The code is retained only to allow decrypting existing keys.
    LegacyTruncated,
    /// Use the full 66 bytes of the ECDH P-521 output.
    Current,
}

/// Calls the boringssl ECDH_compute_key function.
pub fn ecdh_compute_key(
    pub_key: &EC_POINT,
    priv_key: &ECKey,
    version: EcdhComputeKeyVersion,
) -> Result<ZVec, Error> {
    let mut buf = ZVec::new(ECDH_P521_OUTPUT_LEN)?;
    // Safety: ECDHComputeKey() writes at most out_len=buf.len() bytes to buf,
    // and the two keys are valid objects.
    let result = unsafe {
        ECDHComputeKey(buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len(), pub_key, priv_key.0)
    };
    if result == -1 {
        return Err(Error::ECDHComputeKeyFailed);
    }
    let out_len = result.try_into().unwrap();
    // According to the boringssl API, this should never happen.
    if out_len > buf.len() {
        return Err(Error::ECDHComputeKeyFailed);
    }
    // ECDH_compute_key may write fewer than the maximum number of bytes, so we
    // truncate the buffer.
    buf.reduce_len(out_len);

    // If attempting the legacy key decryption method, further truncate the output.
    match version {
        EcdhComputeKeyVersion::LegacyTruncated => buf.reduce_len(LEGACY_TRUNCATED_ECDH_OUTPUT_LEN),
        EcdhComputeKeyVersion::Current => (),
    }
    Ok(buf)
}

/// Calls the boringssl EC_KEY_generate_key function.
pub fn ec_key_generate_key() -> Result<ECKey, Error> {
    // Safety: Creates a new key on its own.
    let key = unsafe { ECKEYGenerateKey() };
    if key.is_null() {
        return Err(Error::ECKEYGenerateKeyFailed);
    }
    Ok(ECKey(key))
}

/// Calls the boringssl EC_KEY_marshal_private_key function.
pub fn ec_key_marshal_private_key(key: &ECKey) -> Result<ZVec, Error> {
    let len = 73; // Empirically observed length of private key
    let mut buf = ZVec::new(len)?;
    // Safety: the key is valid.
    // This will not write past the specified length of the buffer; if the
    // len above is too short, it returns 0.
    let written_len = unsafe { ECKEYMarshalPrivateKey(key.0, buf.as_mut_ptr(), buf.len()) };
    if written_len == len {
        Ok(buf)
    } else {
        Err(Error::ECKEYMarshalPrivateKeyFailed)
    }
}

/// Calls the boringssl EC_KEY_parse_private_key function.
pub fn ec_key_parse_private_key(buf: &[u8]) -> Result<ECKey, Error> {
    // Safety: this will not read past the specified length of the buffer.
    // It fails if less than the whole buffer is consumed.
    let key = unsafe { ECKEYParsePrivateKey(buf.as_ptr(), buf.len()) };
    if key.is_null() {
        Err(Error::ECKEYParsePrivateKeyFailed)
    } else {
        Ok(ECKey(key))
    }
}

/// Calls the boringssl EC_KEY_get0_public_key function.
pub fn ec_key_get0_public_key(key: &ECKey) -> BorrowedECPoint {
    // Safety: The key is valid.
    // This returns a pointer to a key, so we create an immutable variant.
    BorrowedECPoint { data: unsafe { EC_KEY_get0_public_key(key.0) }, phantom: PhantomData }
}

/// Calls the boringssl EC_POINT_point2oct.
pub fn ec_point_point_to_oct(point: &EC_POINT) -> Result<Vec<u8>, Error> {
    // We fix the length to 133 (1 + 2 * field_elem_size), as we get an error if it's too small.
    let len = 133;
    let mut buf = vec![0; len];
    // Safety: EC_POINT_point2oct writes at most len bytes. The point is valid.
    let result = unsafe { ECPOINTPoint2Oct(point, buf.as_mut_ptr(), len) };
    if result == 0 {
        return Err(Error::ECPoint2OctFailed);
    }
    // According to the boringssl API, this should never happen.
    if result > len {
        return Err(Error::ECPoint2OctFailed);
    }
    buf.resize(result, 0);
    Ok(buf)
}

/// Calls the boringssl EC_POINT_oct2point function.
pub fn ec_point_oct_to_point(buf: &[u8]) -> Result<OwnedECPoint, Error> {
    // Safety: The buffer is valid.
    let result = unsafe { ECPOINTOct2Point(buf.as_ptr(), buf.len()) };
    if result.is_null() {
        return Err(Error::ECPoint2OctFailed);
    }
    // Our C wrapper creates a new EC_POINT, so we mark this mutable and free
    // it on drop.
    Ok(OwnedECPoint(result))
}

/// Uses BoringSSL to extract the DER-encoded subject from a DER-encoded X.509 certificate.
pub fn parse_subject_from_certificate(cert_buf: &[u8]) -> Result<Vec<u8>, Error> {
    // Try with a 200-byte output buffer, should be enough in all but bizarre cases.
    let mut retval = vec![0; 200];

    // Safety: extractSubjectFromCertificate reads at most cert_buf.len() bytes from cert_buf and
    // writes at most retval.len() bytes to retval.
    let mut size = unsafe {
        extractSubjectFromCertificate(
            cert_buf.as_ptr(),
            cert_buf.len(),
            retval.as_mut_ptr(),
            retval.len(),
        )
    };

    if size == 0 {
        return Err(Error::ExtractSubjectFailed);
    }

    if size < 0 {
        // Our buffer wasn't big enough.  Make one that is just the right size and try again.
        let negated_size = usize::try_from(-size).map_err(|_e| Error::ExtractSubjectFailed)?;
        retval = vec![0; negated_size];

        // Safety: extractSubjectFromCertificate reads at most cert_buf.len() bytes from cert_buf
        // and writes at most retval.len() bytes to retval.
        size = unsafe {
            extractSubjectFromCertificate(
                cert_buf.as_ptr(),
                cert_buf.len(),
                retval.as_mut_ptr(),
                retval.len(),
            )
        };

        if size <= 0 {
            return Err(Error::ExtractSubjectFailed);
        }
    }

    // Reduce buffer size to the amount written.
    let safe_size = usize::try_from(size).map_err(|_e| Error::ExtractSubjectFailed)?;
    retval.truncate(safe_size);

    Ok(retval)
}

/// Uses BoringSSL to extract the DER-encoded issuer from a DER-encoded X.509 certificate.
pub fn parse_issuer_from_certificate(cert_buf: &[u8]) -> Result<Vec<u8>, Error> {
    // Try with a 200-byte output buffer, should be enough in all but bizarre cases.
    let mut retval = vec![0; 200];

    // Safety: extractIssuerFromCertificate reads at most cert_buf.len() bytes from cert_buf and
    // writes at most retval.len() bytes to retval.
    let mut size = unsafe {
        extractIssuerFromCertificate(
            cert_buf.as_ptr(),
            cert_buf.len(),
            retval.as_mut_ptr(),
            retval.len(),
        )
    };

    if size == 0 {
        return Err(Error::ExtractIssuerFailed);
    }

    if size < 0 {
        // Our buffer wasn't big enough. Make one that is just the right size and try again.
        let negated_size = usize::try_from(-size).map_err(|_e| Error::ExtractIssuerFailed)?;
        retval = vec![0; negated_size];

        // Safety: extractIssuerFromCertificate reads at most cert_buf.len() bytes from cert_buf
        // and writes at most retval.len() bytes to retval.
        size = unsafe {
            extractIssuerFromCertificate(
                cert_buf.as_ptr(),
                cert_buf.len(),
                retval.as_mut_ptr(),
                retval.len(),
            )
        };

        if size <= 0 {
            return Err(Error::ExtractIssuerFailed);
        }
    }

    // Reduce buffer size to the amount written.
    let safe_size = usize::try_from(size).map_err(|_e| Error::ExtractIssuerFailed)?;
    retval.truncate(safe_size);

    Ok(retval)
}

/// Extracts patchlevels from Android attestation extension in a DER-encoded certificate.
///
/// Returns `(os_patchlevel, vendor_patchlevel, boot_patchlevel)`, where each field is `Some(i32)`
/// if found, or `None` otherwise.
pub fn extract_attestation_patchlevels(
    cert_buf: &[u8],
) -> (Option<i32>, Option<i32>, Option<i32>) {
    let mut os_patchlevel = 0i32;
    let mut vendor_patchlevel = 0i32;
    let mut boot_patchlevel = 0i32;
    // Safety: extractAttestationPatchLevels only reads cert_buf and conditionally writes outputs.
    let mask = unsafe {
        extractAttestationPatchLevels(
            cert_buf.as_ptr(),
            cert_buf.len(),
            &mut os_patchlevel,
            &mut vendor_patchlevel,
            &mut boot_patchlevel,
        )
    } as u32;

    let os = if (mask & 0x1) != 0 { Some(os_patchlevel) } else { None };
    let vendor = if (mask & 0x2) != 0 { Some(vendor_patchlevel) } else { None };
    let boot = if (mask & 0x4) != 0 { Some(boot_patchlevel) } else { None };
    (os, vendor, boot)
}


/// Verifies that `child_cert_buf` is signed by `parent_cert_buf`.
pub fn verify_certificate_signed_by(child_cert_buf: &[u8], parent_cert_buf: &[u8]) -> bool {
    // Safety: verifyCertificateSignedBy only reads the provided buffers.
    unsafe {
        verifyCertificateSignedBy(
            child_cert_buf.as_ptr(),
            child_cert_buf.len(),
            parent_cert_buf.as_ptr(),
            parent_cert_buf.len(),
        )
    }
}

/// Returns certificate signature key family:
/// - `Some("rsa")` when certificate signature is RSA-based
/// - `Some("ec")` when certificate signature is EC/ECDSA-based
/// - `None` for unknown/unsupported signature family
pub fn certificate_signature_key_family(cert_buf: &[u8]) -> Option<&'static str> {
    // Safety: getCertificateSignatureKeyFamily only reads the provided buffer.
    match unsafe { getCertificateSignatureKeyFamily(cert_buf.as_ptr(), cert_buf.len()) } {
        1 => Some("rsa"),
        2 => Some("ec"),
        _ => None,
    }
}

/// Returns certificate subject public key family:
/// - `Some("rsa")` when SPKI key is RSA
/// - `Some("ec")` when SPKI key is EC
/// - `None` for unknown/unsupported key family
pub fn certificate_public_key_family(cert_buf: &[u8]) -> Option<&'static str> {
    // Safety: getCertificatePublicKeyFamily only reads the provided buffer.
    match unsafe { getCertificatePublicKeyFamily(cert_buf.as_ptr(), cert_buf.len()) } {
        1 => Some("rsa"),
        2 => Some("ec"),
        _ => None,
    }
}

/// Returns TBSCertificate.signature key family:
/// - `Some("rsa")` when TBS signature algorithm is RSA-based
/// - `Some("ec")` when TBS signature algorithm is EC/ECDSA-based
/// - `None` for unknown/unsupported algorithm family
pub fn certificate_tbs_signature_key_family(cert_buf: &[u8]) -> Option<&'static str> {
    // Safety: getCertificateTbsSignatureKeyFamily only reads the provided buffer.
    match unsafe { getCertificateTbsSignatureKeyFamily(cert_buf.as_ptr(), cert_buf.len()) } {
        1 => Some("rsa"),
        2 => Some("ec"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use keystore2_crypto_bindgen::{AES_gcm_decrypt, AES_gcm_encrypt, CreateKeyId, PBKDF2};

    #[test]
    fn test_wrapper_roundtrip() {
        let key = generate_aes256_key().unwrap();
        let message = b"totally awesome message";
        let (cipher_text, iv, tag) = aes_gcm_encrypt(message, &key).unwrap();
        let message2 = aes_gcm_decrypt(&cipher_text, &iv, &tag, &key).unwrap();
        assert_eq!(message[..], message2[..])
    }

    #[test]
    fn test_encrypt_decrypt() {
        let input = vec![0; 16];
        let mut out = vec![0; 16];
        let mut out2 = vec![0; 16];
        let key = [0; 16];
        let iv = [0; 12];
        let mut tag = vec![0; 16];
        // SAFETY: The various pointers are obtained from references so they are valid, and
        // `AES_gcm_encrypt` and `AES_gcm_decrypt` don't do anything with them after they return.
        unsafe {
            let res = AES_gcm_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                16,
                key.as_ptr(),
                16,
                iv.as_ptr(),
                tag.as_mut_ptr(),
            );
            assert!(res);
            assert_ne!(out, input);
            assert_ne!(tag, input);
            let res = AES_gcm_decrypt(
                out.as_ptr(),
                out2.as_mut_ptr(),
                16,
                key.as_ptr(),
                16,
                iv.as_ptr(),
                tag.as_ptr(),
            );
            assert!(res);
            assert_eq!(out2, input);
        }
    }

    #[test]
    fn test_create_key_id() {
        let blob = [0; 16];
        let mut out: u64 = 0;
        // SAFETY: The pointers are obtained from references so they are valid, the length matches
        // the length of the array, and `CreateKeyId` doesn't access them after it returns.
        unsafe {
            let res = CreateKeyId(blob.as_ptr(), blob.len(), &mut out);
            assert!(res);
            assert_ne!(out, 0);
        }
    }

    #[test]
    fn test_pbkdf2() {
        let mut key = vec![0; 16];
        let pw = [0; 16];
        let salt = [0; 16];
        // SAFETY: The pointers are obtained from references so they are valid, the salt is the
        // expected length, the other lengths match the lengths of the arrays, and `PBKDF2` doesn't
        // access them after it returns.
        unsafe {
            PBKDF2(key.as_mut_ptr(), key.len(), pw.as_ptr(), pw.len(), salt.as_ptr());
        }
        assert_ne!(key, vec![0; 16]);
    }

    #[test]
    fn test_hkdf() {
        let result = hkdf_extract(&[0; 16], &[0; 16]);
        assert!(result.is_ok());
        for out_len in 4..=8 {
            let result = hkdf_expand(out_len, &[0; 16], &[0; 16]);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().len(), out_len);
        }
    }

    #[test]
    fn test_ec() -> Result<(), Error> {
        let priv0 = ec_key_generate_key()?;
        assert!(!priv0.0.is_null());
        let pub0 = ec_key_get0_public_key(&priv0);

        let priv1 = ec_key_generate_key()?;
        let pub1 = ec_key_get0_public_key(&priv1);

        let priv0s = ec_key_marshal_private_key(&priv0)?;
        let pub0s = ec_point_point_to_oct(pub0.get_point())?;
        let pub1s = ec_point_point_to_oct(pub1.get_point())?;

        let priv0 = ec_key_parse_private_key(&priv0s)?;
        let pub0 = ec_point_oct_to_point(&pub0s)?;
        let pub1 = ec_point_oct_to_point(&pub1s)?;

        for version in [EcdhComputeKeyVersion::Current, EcdhComputeKeyVersion::LegacyTruncated] {
            let left_key = ecdh_compute_key(pub0.get_point(), &priv1, version)?;
            let right_key = ecdh_compute_key(pub1.get_point(), &priv0, version)?;
            assert_eq!(left_key, right_key);
        }

        Ok(())
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"This is the key";
        let msg1 = b"This is a message";
        let msg2 = b"This is another message";
        let tag1a = hmac_sha256(key, msg1).unwrap();
        assert_eq!(tag1a.len(), HMAC_SHA256_LEN);
        let tag1b = hmac_sha256(key, msg1).unwrap();
        assert_eq!(tag1a, tag1b);
        let tag2 = hmac_sha256(key, msg2).unwrap();
        assert_eq!(tag2.len(), HMAC_SHA256_LEN);
        assert_ne!(tag1a, tag2);
    }
}
