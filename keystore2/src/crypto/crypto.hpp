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
int extractSubjectFromCertificate(const uint8_t* cert_buf, size_t cert_len,
                                  uint8_t* subject_buf, size_t subject_buf_len);

// Parse a DER-encoded X.509 certificate contained in cert_buf, with length
// cert_len, extract the issuer, DER-encode it and write the result to
// issuer_buf, which has issuer_buf_len capacity.
int extractIssuerFromCertificate(const uint8_t* cert_buf, size_t cert_len,
                                 uint8_t* issuer_buf, size_t issuer_buf_len);

// Verify that `child_cert_buf` is signed by `parent_cert_buf` public key.
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
int extractAttestationPatchLevels(const uint8_t* cert_buf, size_t cert_len, int32_t* out_os_patchlevel,
                                  int32_t* out_vendor_patchlevel, int32_t* out_boot_patchlevel);

#endif  //  __CRYPTO_H__
