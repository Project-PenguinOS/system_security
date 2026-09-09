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

#define LOG_TAG "keystore2"

#include "crypto.hpp"

#include "certificate_utils.h"

#include <android-base/properties.h>
#include <assert.h>
#include <log/log.h>
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/pkcs8.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <memory>
#include <string_view>
#include <vector>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

// Copied from system/security/keystore/blob.h.

constexpr size_t kGcmTagLength = 128 / 8;
constexpr size_t kAes128KeySizeBytes = 128 / 8;

// Copied from system/security/keystore/blob.cpp.

#if defined(__clang__)
#define OPTNONE __attribute__((optnone))
#elif defined(__GNUC__)
#define OPTNONE __attribute__((optimize("O0")))
#else
#error Need a definition for OPTNONE
#endif

class ArrayEraser {
  public:
    ArrayEraser(uint8_t* arr, size_t size) : mArr(arr), mSize(size) {}
    OPTNONE ~ArrayEraser() { std::fill(mArr, mArr + mSize, 0); }

  private:
    volatile uint8_t* mArr;
    size_t mSize;
};

/**
 * Returns a EVP_CIPHER appropriate for the given key size.
 */
const EVP_CIPHER* getAesCipherForKey(size_t key_size) {
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if (key_size == kAes128KeySizeBytes) {
        cipher = EVP_aes_128_gcm();
    }
    return cipher;
}

bool hmacSha256(const uint8_t* key, size_t key_size, const uint8_t* msg, size_t msg_size,
                uint8_t* out, size_t out_size) {
    const EVP_MD* digest = EVP_sha256();
    unsigned int actual_out_size = out_size;
    uint8_t* p = HMAC(digest, key, key_size, msg, msg_size, out, &actual_out_size);
    return (p != nullptr);
}

bool randomBytes(uint8_t* out, size_t len) {
    return RAND_bytes(out, len);
}

/*
 * Encrypt 'len' data at 'in' with AES-GCM, using 128-bit or 256-bit key at 'key', 96-bit IV at
 * 'iv' and write output to 'out' (which may be the same location as 'in') and 128-bit tag to
 * 'tag'.
 */
bool AES_gcm_encrypt(const uint8_t* in, uint8_t* out, size_t len, const uint8_t* key,
                     size_t key_size, const uint8_t* iv, uint8_t* tag) {

    // There can be 128-bit and 256-bit keys
    const EVP_CIPHER* cipher = getAesCipherForKey(key_size);

    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

    EVP_EncryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);

    std::vector<uint8_t> out_tmp(len);
    uint8_t* out_pos = out_tmp.data();
    int out_len;

    EVP_EncryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    EVP_EncryptFinal_ex(ctx.get(), out_pos, &out_len);
    out_pos += out_len;
    if (out_pos - out_tmp.data() != static_cast<ssize_t>(len)) {
        ALOGD("Encrypted ciphertext is the wrong size, expected %zu, got %zd", len,
              out_pos - out_tmp.data());
        return false;
    }

    std::copy(out_tmp.data(), out_pos, out);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagLength, tag);

    return true;
}

/*
 * Decrypt 'len' data at 'in' with AES-GCM, using 128-bit or 256-bit key at 'key', 96-bit IV at
 * 'iv', checking 128-bit tag at 'tag' and writing plaintext to 'out'(which may be the same
 * location as 'in').
 */
bool AES_gcm_decrypt(const uint8_t* in, uint8_t* out, size_t len, const uint8_t* key,
                     size_t key_size, const uint8_t* iv, const uint8_t* tag) {

    // There can be 128-bit and 256-bit keys
    const EVP_CIPHER* cipher = getAesCipherForKey(key_size);

    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

    EVP_DecryptInit_ex(ctx.get(), cipher, nullptr /* engine */, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0 /* no padding needed with GCM */);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagLength, const_cast<uint8_t*>(tag));

    std::vector<uint8_t> out_tmp(len);
    ArrayEraser out_eraser(out_tmp.data(), len);
    uint8_t* out_pos = out_tmp.data();
    int out_len;

    EVP_DecryptUpdate(ctx.get(), out_pos, &out_len, in, len);
    out_pos += out_len;
    if (!EVP_DecryptFinal_ex(ctx.get(), out_pos, &out_len)) {
        // No error log here; this is expected when trying two different keys to see which one
        // works.  The callers handle the error appropriately.
        return false;
    }
    out_pos += out_len;
    if (out_pos - out_tmp.data() != static_cast<ssize_t>(len)) {
        ALOGE("Encrypted plaintext is the wrong size, expected %zu, got %zd", len,
              out_pos - out_tmp.data());
        return false;
    }

    std::copy(out_tmp.data(), out_pos, out);

    return true;
}

// Copied from system/security/keystore/keymaster_enforcement.cpp.

class EvpMdCtx {
  public:
    EvpMdCtx() { EVP_MD_CTX_init(&ctx_); }
    ~EvpMdCtx() { EVP_MD_CTX_cleanup(&ctx_); }

    EVP_MD_CTX* get() { return &ctx_; }

  private:
    EVP_MD_CTX ctx_;
};

bool CreateKeyId(const uint8_t* key_blob, size_t len, km_id_t* out_id) {
    EvpMdCtx ctx;

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr /* ENGINE */) &&
        EVP_DigestUpdate(ctx.get(), key_blob, len) &&
        EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
        assert(hash_len >= sizeof(*out_id));
        memcpy(out_id, hash, sizeof(*out_id));
        return true;
    }

    return false;
}

// Copied from system/security/keystore/user_state.h

static constexpr size_t SALT_SIZE = 16;

// Copied from system/security/keystore/user_state.cpp.

void PBKDF2(uint8_t* key, size_t key_len, const char* pw, size_t pw_len, const uint8_t* salt) {
    const EVP_MD* digest = EVP_sha256();

    // SHA1 was used prior to increasing the key size
    if (key_len == kAes128KeySizeBytes) {
        digest = EVP_sha1();
    }

    PKCS5_PBKDF2_HMAC(pw, pw_len, salt, SALT_SIZE, 8192, digest, key_len, key);
}

// New code.

bool HKDFExtract(uint8_t* out_key, size_t* out_len, const uint8_t* secret, size_t secret_len,
                 const uint8_t* salt, size_t salt_len) {
    const EVP_MD* digest = EVP_sha256();
    auto result = HKDF_extract(out_key, out_len, digest, secret, secret_len, salt, salt_len);
    return result == 1;
}

bool HKDFExpand(uint8_t* out_key, size_t out_len, const uint8_t* prk, size_t prk_len,
                const uint8_t* info, size_t info_len) {
    const EVP_MD* digest = EVP_sha256();
    auto result = HKDF_expand(out_key, out_len, digest, prk, prk_len, info, info_len);
    return result == 1;
}

int ECDHComputeKey(void* out, size_t out_len, const EC_POINT* pub_key, const EC_KEY* priv_key) {
    return ECDH_compute_key(out, out_len, pub_key, priv_key, nullptr);
}

EC_KEY* ECKEYGenerateKey() {
    EC_KEY* key = EC_KEY_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    EC_KEY_set_group(key, group);
    auto result = EC_KEY_generate_key(key);
    if (result == 0) {
        EC_GROUP_free(group);
        EC_KEY_free(key);
        return nullptr;
    }
    return key;
}

size_t ECKEYMarshalPrivateKey(const EC_KEY* priv_key, uint8_t* buf, size_t len) {
    CBB cbb;
    size_t out_len;
    if (!CBB_init_fixed(&cbb, buf, len) ||
        !EC_KEY_marshal_private_key(&cbb, priv_key, EC_PKEY_NO_PARAMETERS | EC_PKEY_NO_PUBKEY) ||
        !CBB_finish(&cbb, nullptr, &out_len)) {
        return 0;
    } else {
        return out_len;
    }
}

EC_KEY* ECKEYParsePrivateKey(const uint8_t* buf, size_t len) {
    CBS cbs;
    CBS_init(&cbs, buf, len);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    auto result = EC_KEY_parse_private_key(&cbs, group);
    EC_GROUP_free(group);
    if (result != nullptr && CBS_len(&cbs) != 0) {
        EC_KEY_free(result);
        return nullptr;
    }
    return result;
}

size_t ECPOINTPoint2Oct(const EC_POINT* point, uint8_t* buf, size_t len) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    auto result = EC_POINT_point2oct(group, point, form, buf, len, nullptr);
    EC_GROUP_free(group);
    return result;
}

EC_POINT* ECPOINTOct2Point(const uint8_t* buf, size_t len) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    EC_POINT* point = EC_POINT_new(group);
    auto result = EC_POINT_oct2point(group, point, buf, len, nullptr);
    EC_GROUP_free(group);
    if (result == 0) {
        EC_POINT_free(point);
        return nullptr;
    }
    return point;
}

int extractSubjectFromCertificate(const uint8_t* cert_buf, size_t cert_len, uint8_t* subject_buf,
                                  size_t subject_buf_len) {
    if (!cert_buf || !subject_buf) {
        ALOGE("extractSubjectFromCertificate: received null pointer");
        return 0;
    }

    const uint8_t* p = cert_buf;
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr /* Allocate X509 struct */, &p, cert_len));
    if (!cert) {
        ALOGE("extractSubjectFromCertificate: failed to parse certificate");
        return 0;
    }

    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (!subject) {
        ALOGE("extractSubjectFromCertificate: failed to retrieve subject name");
        return 0;
    }

    int subject_len = i2d_X509_NAME(subject, nullptr /* Don't copy the data */);
    if (subject_len < 0) {
        ALOGE("extractSubjectFromCertificate: error obtaining encoded subject name length");
        return 0;
    }

    if (subject_len > subject_buf_len) {
        // Return the subject length, negated, so the caller knows how much
        // buffer space is required.
        ALOGI("extractSubjectFromCertificate: needed %d bytes for subject, caller provided %zu",
              subject_len, subject_buf_len);
        return -subject_len;
    }

    // subject_buf has enough space.
    uint8_t* tmp = subject_buf;
    return i2d_X509_NAME(subject, &tmp);
}

int extractIssuerFromCertificate(const uint8_t* cert_buf, size_t cert_len, uint8_t* issuer_buf,
                                 size_t issuer_buf_len) {
    if (!cert_buf || !issuer_buf) {
        ALOGE("extractIssuerFromCertificate: received null pointer");
        return 0;
    }

    const uint8_t* p = cert_buf;
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr /* Allocate X509 struct */, &p, cert_len));
    if (!cert) {
        ALOGE("extractIssuerFromCertificate: failed to parse certificate");
        return 0;
    }

    X509_NAME* issuer = X509_get_issuer_name(cert.get());
    if (!issuer) {
        ALOGE("extractIssuerFromCertificate: failed to retrieve issuer name");
        return 0;
    }

    int issuer_len = i2d_X509_NAME(issuer, nullptr /* Don't copy the data */);
    if (issuer_len < 0) {
        ALOGE("extractIssuerFromCertificate: error obtaining encoded issuer name length");
        return 0;
    }

    if (issuer_len > issuer_buf_len) {
        ALOGI("extractIssuerFromCertificate: needed %d bytes for issuer, caller provided %zu",
              issuer_len, issuer_buf_len);
        return -issuer_len;
    }

    uint8_t* tmp = issuer_buf;
    return i2d_X509_NAME(issuer, &tmp);
}

static void appendDerLength(std::vector<uint8_t>* out, size_t len) {
    if (len < 0x80) {
        out->push_back(static_cast<uint8_t>(len));
        return;
    }
    uint8_t tmp[8];
    size_t n = 0;
    size_t v = len;
    while (v > 0) {
        tmp[n++] = static_cast<uint8_t>(v & 0xff);
        v >>= 8;
    }
    out->push_back(static_cast<uint8_t>(0x80 | n));
    while (n > 0) {
        out->push_back(tmp[--n]);
    }
}

static std::vector<uint8_t> makeDerTlv(uint8_t tag, const std::vector<uint8_t>& value) {
    std::vector<uint8_t> out;
    out.reserve(1 + 5 + value.size());
    out.push_back(tag);
    appendDerLength(&out, value.size());
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

static bool parseOneDerElement(const uint8_t* buf, size_t len, size_t* total_len, size_t* hdr_len,
                               uint32_t* tag_number, bool* tag_ctx_specific) {
    if (!buf || len < 2 || !total_len || !hdr_len || !tag_number || !tag_ctx_specific) return false;

    size_t pos = 0;
    const uint8_t first = buf[pos++];
    *tag_ctx_specific = (first & 0xC0) == 0x80;
    uint32_t tag = first & 0x1F;
    if (tag == 0x1F) {
        tag = 0;
        bool saw_last = false;
        while (pos < len) {
            const uint8_t b = buf[pos++];
            tag = (tag << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                saw_last = true;
                break;
            }
        }
        if (!saw_last) return false;
    }
    *tag_number = tag;

    if (pos >= len) return false;
    uint8_t l = buf[pos++];
    size_t value_len = 0;
    if ((l & 0x80) == 0) {
        value_len = l;
    } else {
        size_t n = l & 0x7F;
        if (n == 0 || n > sizeof(size_t) || pos + n > len) return false;
        for (size_t i = 0; i < n; ++i) {
            value_len = (value_len << 8) | buf[pos++];
        }
    }
    if (pos + value_len > len) return false;
    *hdr_len = pos;
    *total_len = pos + value_len;
    return true;
}

static bool parseDerIntegerToInt32(const uint8_t* der, size_t der_len, int32_t* out) {
    if (!der || der_len < 3 || !out) return false;
    if (der[0] != 0x02) return false;  // INTEGER

    size_t total_len = 0, hdr_len = 0;
    uint32_t tag = 0;
    bool is_ctx = false;
    if (!parseOneDerElement(der, der_len, &total_len, &hdr_len, &tag, &is_ctx)) return false;
    if (total_len != der_len || is_ctx || tag != 0x02) return false;

    const uint8_t* value = der + hdr_len;
    const size_t value_len = der_len - hdr_len;
    if (value_len == 0 || value_len > 5) return false;

    int64_t acc = 0;
    for (size_t i = 0; i < value_len; ++i) {
        acc = (acc << 8) | value[i];
    }

    if ((value[0] & 0x80) != 0) {
        // Two's complement sign extension for negative values.
        const int shift = static_cast<int>((8 - value_len) * 8);
        acc = (acc << shift) >> shift;
    }

    if (acc < INT32_MIN || acc > INT32_MAX) return false;
    *out = static_cast<int32_t>(acc);
    return true;
}

static uint32_t extractPatchLevelsFromAuthorizationListDer(const std::vector<uint8_t>& auth_list_der,
                                                           int32_t* out_os_patchlevel,
                                                           int32_t* out_vendor_patchlevel,
                                                           int32_t* out_boot_patchlevel) {
    if (auth_list_der.empty() || auth_list_der[0] != 0x30) {
        return 0;
    }

    size_t seq_total = 0, seq_hdr = 0;
    uint32_t seq_tag = 0;
    bool seq_ctx = false;
    if (!parseOneDerElement(auth_list_der.data(), auth_list_der.size(), &seq_total, &seq_hdr, &seq_tag,
                            &seq_ctx)) {
        return 0;
    }
    if (seq_total != auth_list_der.size() || seq_ctx || seq_tag != 0x10) {
        return 0;
    }

    uint32_t mask = 0;
    const uint8_t* items = auth_list_der.data() + seq_hdr;
    const size_t items_len = auth_list_der.size() - seq_hdr;
    size_t pos = 0;
    while (pos < items_len) {
        size_t el_total = 0, el_hdr = 0;
        uint32_t tag_no = 0;
        bool is_ctx = false;
        if (!parseOneDerElement(items + pos, items_len - pos, &el_total, &el_hdr, &tag_no, &is_ctx)) {
            return mask;
        }
        if (is_ctx && (tag_no == 706 || tag_no == 718 || tag_no == 719)) {
            const uint8_t* inner = items + pos + el_hdr;
            const size_t inner_len = el_total - el_hdr;
            int32_t value = 0;
            if (parseDerIntegerToInt32(inner, inner_len, &value)) {
                if (tag_no == 706) {
                    if (out_os_patchlevel) *out_os_patchlevel = value;
                    mask |= 0x1;
                } else if (tag_no == 718) {
                    if (out_vendor_patchlevel) *out_vendor_patchlevel = value;
                    mask |= 0x2;
                } else if (tag_no == 719) {
                    if (out_boot_patchlevel) *out_boot_patchlevel = value;
                    mask |= 0x4;
                }
            }
        }
        pos += el_total;
    }
    return mask;
}

bool verifyCertificateSignedBy(const uint8_t* child_cert_buf, size_t child_cert_len,
                               const uint8_t* parent_cert_buf, size_t parent_cert_len) {
    if (!child_cert_buf || !parent_cert_buf) {
        ALOGE("verifyCertificateSignedBy: null pointer input");
        return false;
    }

    const uint8_t* child_p = child_cert_buf;
    bssl::UniquePtr<X509> child(d2i_X509(nullptr, &child_p, static_cast<long>(child_cert_len)));
    if (!child) {
        ALOGE("verifyCertificateSignedBy: failed to parse child cert");
        return false;
    }

    const uint8_t* parent_p = parent_cert_buf;
    bssl::UniquePtr<X509> parent(d2i_X509(nullptr, &parent_p, static_cast<long>(parent_cert_len)));
    if (!parent) {
        ALOGE("verifyCertificateSignedBy: failed to parse parent cert");
        return false;
    }

    bssl::UniquePtr<EVP_PKEY> parent_pubkey(X509_get_pubkey(parent.get()));
    if (!parent_pubkey) {
        ALOGE("verifyCertificateSignedBy: failed to get parent pubkey");
        return false;
    }

    if (X509_verify(child.get(), parent_pubkey.get()) != 1) {
        ALOGE("verifyCertificateSignedBy: certificate signature verification failed");
        return false;
    }

    return true;
}

int extractAttestationPatchLevels(const uint8_t* cert_buf, size_t cert_len, int32_t* out_os_patchlevel,
                                  int32_t* out_vendor_patchlevel, int32_t* out_boot_patchlevel) {
    if (!cert_buf || cert_len == 0) {
        ALOGE("extractAttestationPatchLevels: invalid cert input");
        return 0;
    }

    const uint8_t* p = cert_buf;
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &p, static_cast<long>(cert_len)));
    if (!cert) {
        ALOGE("extractAttestationPatchLevels: failed to parse cert");
        return 0;
    }

    ASN1_OBJECT* att_oid_obj = OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1);
    if (!att_oid_obj) return 0;
    int ext_idx = X509_get_ext_by_OBJ(cert.get(), att_oid_obj, -1);
    ASN1_OBJECT_free(att_oid_obj);
    if (ext_idx < 0) return 0;

    X509_EXTENSION* ext = X509_get_ext(cert.get(), ext_idx);
    if (!ext) return 0;
    ASN1_OCTET_STRING* ext_data = X509_EXTENSION_get_data(ext);
    if (!ext_data || !ext_data->data || ext_data->length <= 0) return 0;

    const uint8_t* ext_ptr = ext_data->data;
    STACK_OF(ASN1_TYPE)* key_desc = d2i_ASN1_SEQUENCE_ANY(nullptr, &ext_ptr, ext_data->length);
    if (!key_desc) return 0;

    uint32_t mask = 0;
    for (int i = 0; i < sk_ASN1_TYPE_num(key_desc); ++i) {
        if (i != 6 && i != 7) continue;  // softwareEnforced and teeEnforced
        ASN1_TYPE* item = sk_ASN1_TYPE_value(key_desc, i);
        if (!item) continue;
        const int n = i2d_ASN1_TYPE(item, nullptr);
        if (n <= 0) continue;
        std::vector<uint8_t> buf(static_cast<size_t>(n));
        uint8_t* ptr = buf.data();
        if (i2d_ASN1_TYPE(item, &ptr) <= 0) continue;
        mask |= extractPatchLevelsFromAuthorizationListDer(buf, out_os_patchlevel, out_vendor_patchlevel,
                                                           out_boot_patchlevel);
    }

    sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
    return static_cast<int>(mask);
}

int getCertificateSignatureKeyFamily(const uint8_t* cert_buf, size_t cert_len) {
    if (!cert_buf) {
        ALOGE("getCertificateSignatureKeyFamily: null pointer input");
        return 0;
    }

    const uint8_t* p = cert_buf;
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &p, static_cast<long>(cert_len)));
    if (!cert) {
        ALOGE("getCertificateSignatureKeyFamily: failed to parse cert");
        return 0;
    }

    int sig_nid = X509_get_signature_nid(cert.get());
    if (sig_nid == NID_undef) {
        ALOGE("getCertificateSignatureKeyFamily: certificate signature nid undefined");
        return 0;
    }

    int pkey_nid = NID_undef;
    if (OBJ_find_sigid_algs(sig_nid, nullptr, &pkey_nid) != 1) {
        ALOGE("getCertificateSignatureKeyFamily: failed to derive signature key algorithm");
        return 0;
    }

    switch (EVP_PKEY_type(pkey_nid)) {
    case EVP_PKEY_RSA:
        return 1;
    case EVP_PKEY_EC:
        return 2;
    default:
        return 0;
    }
}

int getCertificatePublicKeyFamily(const uint8_t* cert_buf, size_t cert_len) {
    if (!cert_buf) {
        ALOGE("getCertificatePublicKeyFamily: null pointer input");
        return 0;
    }

    const uint8_t* p = cert_buf;
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &p, static_cast<long>(cert_len)));
    if (!cert) {
        ALOGE("getCertificatePublicKeyFamily: failed to parse cert");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> pubkey(X509_get_pubkey(cert.get()));
    if (!pubkey) {
        ALOGE("getCertificatePublicKeyFamily: failed to extract public key");
        return 0;
    }

    switch (EVP_PKEY_base_id(pubkey.get())) {
    case EVP_PKEY_RSA:
        return 1;
    case EVP_PKEY_EC:
        return 2;
    default:
        return 0;
    }
}

int getCertificateTbsSignatureKeyFamily(const uint8_t* cert_buf, size_t cert_len) {
    if (!cert_buf) {
        ALOGE("getCertificateTbsSignatureKeyFamily: null pointer input");
        return 0;
    }

    const uint8_t* p = cert_buf;
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &p, static_cast<long>(cert_len)));
    if (!cert) {
        ALOGE("getCertificateTbsSignatureKeyFamily: failed to parse cert");
        return 0;
    }

    const X509_ALGOR* tbs_sig_alg = X509_get0_tbs_sigalg(cert.get());
    if (!tbs_sig_alg || !tbs_sig_alg->algorithm) {
        ALOGE("getCertificateTbsSignatureKeyFamily: missing tbs signature algorithm");
        return 0;
    }

    int sig_nid = OBJ_obj2nid(tbs_sig_alg->algorithm);
    if (sig_nid == NID_undef) {
        ALOGE("getCertificateTbsSignatureKeyFamily: tbs signature nid undefined");
        return 0;
    }

    int pkey_nid = NID_undef;
    if (OBJ_find_sigid_algs(sig_nid, nullptr, &pkey_nid) != 1) {
        ALOGE("getCertificateTbsSignatureKeyFamily: failed to derive tbs signature key algorithm");
        return 0;
    }

    switch (EVP_PKEY_type(pkey_nid)) {
    case EVP_PKEY_RSA:
        return 1;
    case EVP_PKEY_EC:
        return 2;
    default:
        return 0;
    }
}

