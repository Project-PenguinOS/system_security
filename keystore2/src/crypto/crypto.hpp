/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

extern "C" {
  bool hmacSha256(const uint8_t* key, size_t key_size, const uint8_t* msg, size_t msg_size,
                  uint8_t* out, size_t out_size);
  bool randomBytes(uint8_t* out, size_t len);
  bool AES_gcm_encrypt(const uint8_t* in, uint8_t* out, size_t len,
                       const uint8_t* key, size_t key_size, const uint8_t* iv, uint8_t* tag);
  bool AES_gcm_decrypt(const uint8_t* in, uint8_t* out, size_t len,
                       const uint8_t* key, size_t key_size, const uint8_t* iv,
                       const uint8_t* tag);

  // Copied from system/security/keystore/keymaster_enforcement.h.
  typedef uint64_t km_id_t;

  bool CreateKeyId(const uint8_t* key_blob, size_t len, km_id_t* out_id);

  // The salt parameter must be non-nullptr and point to 16 bytes of data.
  void PBKDF2(uint8_t* key, size_t key_len, const char* pw, size_t pw_len, const uint8_t* salt);

  #include "openssl/digest.h"
  #include "openssl/ec_key.h"

  bool HKDFExtract(uint8_t *out_key, size_t *out_len,
                   const uint8_t *secret, size_t secret_len,
                   const uint8_t *salt, size_t salt_len);

  bool HKDFExpand(uint8_t *out_key, size_t out_len,
                  const uint8_t *prk, size_t prk_len,
                  const uint8_t *info, size_t info_len);

  int ECDHComputeKey(void *out, size_t out_len, const EC_POINT *pub_key, const EC_KEY *priv_key);

  EC_KEY* ECKEYGenerateKey();

  size_t ECKEYMarshalPrivateKey(const EC_KEY *priv_key, uint8_t *buf, size_t len);

  EC_KEY* ECKEYParsePrivateKey(const uint8_t *buf, size_t len);

  size_t ECPOINTPoint2Oct(const EC_POINT *point, uint8_t *buf, size_t len);

  EC_POINT* ECPOINTOct2Point(const uint8_t *buf, size_t len);

}

// Parse a DER-encoded X.509 certificate contained in cert_buf, with length
// cert_len, extract the subject, DER-encode it and write the result to
// subject_buf, which has subject_buf_len capacity.
//
// Because the length of the subject is unknown, and because we'd like to (a) be
// able to handle subjects of any size and (b) avoid parsing the certificate
// twice most of the time, once to discover the length and once to parse it, the
// return value is overloaded.
//
// If the return value > 0 it specifies the number of bytes written into
// subject_buf; the operation was successful.
//
// If the return value == 0, certificate parsing failed unrecoverably.  The
// reason will be logged.
//
// If the return value < 0, the operation failed because the subject size >
// subject_buf_len.  The return value is -(subject_size), where subject_size is
// the size of the extracted DER-encoded subject field.  Call
// extractSubjectFromCertificate again with a sufficiently-large buffer.
int extractSubjectFromCertificate(const uint8_t* cert_buf, size_t cert_len,
                                  uint8_t* subject_buf, size_t subject_buf_len);

// Parse a DER-encoded X.509 certificate contained in cert_buf, with length
// cert_len, extract the issuer, DER-encode it and write the result to
// issuer_buf, which has issuer_buf_len capacity.
//
// Return value semantics are identical to extractSubjectFromCertificate:
// - > 0: success, number of bytes written
// - = 0: unrecoverable failure
// - < 0: output buffer too small, required size is -ret
int extractIssuerFromCertificate(const uint8_t* cert_buf, size_t cert_len,
                                 uint8_t* issuer_buf, size_t issuer_buf_len);

// Re-sign a DER-encoded leaf certificate with a private key and issuer certificate.
//
// `signing_key_buf` supports either PEM text ("BEGIN PRIVATE KEY") or DER key bytes.
//
// Return value semantics:
// - > 0: success, number of bytes written to out_cert_buf.
// - = 0: failure.
// - < 0: output buffer too small; required size is `-ret`.
int resignLeafCertificate(const uint8_t* leaf_cert_buf, size_t leaf_cert_len,
                          const uint8_t* signing_cert_buf, size_t signing_cert_len,
                          const uint8_t* signing_key_buf, size_t signing_key_len,
                          uint8_t* out_cert_buf, size_t out_cert_buf_len);

// Verify that `child_cert_buf` is signed by `parent_cert_buf` public key.
//
// Return true on successful verification, false otherwise.
bool verifyCertificateSignedBy(const uint8_t* child_cert_buf, size_t child_cert_len,
                               const uint8_t* parent_cert_buf, size_t parent_cert_len);

// Return signature key family used by certificate's signature algorithm:
// - 1: RSA
// - 2: EC/ECDSA
// - 0: unknown or parse failure
int getCertificateSignatureKeyFamily(const uint8_t* cert_buf, size_t cert_len);

// Return public key family of certificate SubjectPublicKeyInfo:
// - 1: RSA
// - 2: EC/ECDSA
// - 0: unknown or parse failure
int getCertificatePublicKeyFamily(const uint8_t* cert_buf, size_t cert_len);

// Return signature key family encoded in TBSCertificate.signature field:
// - 1: RSA
// - 2: EC/ECDSA
// - 0: unknown or parse failure
int getCertificateTbsSignatureKeyFamily(const uint8_t* cert_buf, size_t cert_len);

// Extract patch levels from Android attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
//
// Output pointers may be null. If non-null and the corresponding field is found, it is written.
//
// Return value is a bitmask:
// - bit 0 (0x1): OS_PATCHLEVEL found
// - bit 1 (0x2): VENDOR_PATCHLEVEL found
// - bit 2 (0x4): BOOT_PATCHLEVEL found
//
// Returns 0 if parsing fails or none of the fields are found.
int extractAttestationPatchLevels(const uint8_t* cert_buf, size_t cert_len, int32_t* out_os_patchlevel,
                                  int32_t* out_vendor_patchlevel, int32_t* out_boot_patchlevel);

// Generate a software-backed key and signed attestation certificate.
// key_type: 1 = RSA, 2 = EC (NIST P-256)
// rsa_key_size: e.g. 2048
// challenge: attestation challenge bytes
// signing_cert_buf, signing_cert_len: signer certificate (DER)
// signing_key_buf, signing_key_len: signer private key (DER or PEM)
// is_attest_key: whether KeyPurpose::ATTEST_KEY is requested
// out_privkey_buf, out_privkey_buf_len: buffer to receive PKCS#8 private key
// out_privkey_len: written length of PKCS#8 private key
// out_cert_buf, out_cert_buf_len: buffer to receive DER X.509 certificate
// Return value: > 0 (cert length on success), 0 on failure, < 0 if cert buffer too small (-needed)
int generateSoftwareAttestedKey(
        int key_type, int rsa_key_size,
        const uint8_t* challenge, size_t challenge_len,
        const uint8_t* signing_cert_buf, size_t signing_cert_len,
        const uint8_t* signing_key_buf, size_t signing_key_len,
        int is_attest_key,
        uint8_t* out_privkey_buf, size_t out_privkey_buf_len,
        size_t* out_privkey_len,
        uint8_t* out_cert_buf, size_t out_cert_buf_len);

#endif  //  __CRYPTO_H__
