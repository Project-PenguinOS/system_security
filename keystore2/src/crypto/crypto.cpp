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

static bool base64Decode(const std::string& input, std::vector<uint8_t>* out) {
    if (!out) return false;
    out->clear();
    if (input.empty()) return true;

    size_t out_len = 0;
    if (EVP_DecodedLength(&out_len, input.size()) != 1) {
        return false;
    }
    out->resize(out_len);
    if (EVP_DecodeBase64(out->data(), &out_len, out_len,
                         reinterpret_cast<const uint8_t*>(input.data()), input.size()) != 1) {
        out->clear();
        return false;
    }
    out->resize(out_len);
    return true;
}

static bssl::UniquePtr<EVP_PKEY> parseSigningKey(const uint8_t* key_buf, size_t key_len) {
    if (!key_buf || key_len == 0) {
        return nullptr;
    }

    std::string raw_str(reinterpret_cast<const char*>(key_buf), key_len);
    if (raw_str.find("-----BEGIN") != std::string::npos) {
        std::string cleaned_pem;
        std::istringstream stream(raw_str);
        std::string line;
        while (std::getline(stream, line)) {
            size_t first = line.find_first_not_of(" \t\r\n");
            if (first != std::string::npos) {
                size_t last = line.find_last_not_of(" \t\r\n");
                cleaned_pem += line.substr(first, (last - first + 1)) + "\n";
            }
        }

        bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(cleaned_pem.data(), static_cast<int>(cleaned_pem.size())));
        if (bio) {
            bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
            if (pkey) return pkey;
        }

        bssl::UniquePtr<BIO> ec_bio(BIO_new_mem_buf(cleaned_pem.data(), static_cast<int>(cleaned_pem.size())));
        if (ec_bio) {
            bssl::UniquePtr<EC_KEY> ec(PEM_read_bio_ECPrivateKey(ec_bio.get(), nullptr, nullptr, nullptr));
            if (ec) {
                bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
                if (pkey && EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get())) {
                    return pkey;
                }
            }
        }

        bssl::UniquePtr<BIO> rsa_bio(BIO_new_mem_buf(cleaned_pem.data(), static_cast<int>(cleaned_pem.size())));
        if (rsa_bio) {
            bssl::UniquePtr<RSA> rsa(PEM_read_bio_RSAPrivateKey(rsa_bio.get(), nullptr, nullptr, nullptr));
            if (rsa) {
                bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
                if (pkey && EVP_PKEY_set1_RSA(pkey.get(), rsa.get())) {
                    return pkey;
                }
            }
        }

        std::string b64_payload;
        std::istringstream pem_stream(cleaned_pem);
        while (std::getline(pem_stream, line)) {
            if (line.rfind("-----", 0) == 0) continue;
            for (char c : line) {
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                    b64_payload.push_back(c);
                }
            }
        }
        std::vector<uint8_t> der_bytes;
        if (base64Decode(b64_payload, &der_bytes) && !der_bytes.empty()) {
            const uint8_t* p = der_bytes.data();
            bssl::UniquePtr<EVP_PKEY> pkey(d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(der_bytes.size())));
            if (pkey) return pkey;

            p = der_bytes.data();
            bssl::UniquePtr<EC_KEY> ec(d2i_ECPrivateKey(nullptr, &p, static_cast<long>(der_bytes.size())));
            if (ec) {
                bssl::UniquePtr<EVP_PKEY> ec_pkey(EVP_PKEY_new());
                if (ec_pkey && EVP_PKEY_set1_EC_KEY(ec_pkey.get(), ec.get())) return ec_pkey;
            }

            p = der_bytes.data();
            bssl::UniquePtr<RSA> rsa(d2i_RSAPrivateKey(nullptr, &p, static_cast<long>(der_bytes.size())));
            if (rsa) {
                bssl::UniquePtr<EVP_PKEY> rsa_pkey(EVP_PKEY_new());
                if (rsa_pkey && EVP_PKEY_set1_RSA(rsa_pkey.get(), rsa.get())) return rsa_pkey;
            }
        }
    }

    const uint8_t* p = key_buf;
    bssl::UniquePtr<EVP_PKEY> pkey(d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(key_len)));
    if (pkey) return pkey;

    p = key_buf;
    bssl::UniquePtr<EC_KEY> ec(d2i_ECPrivateKey(nullptr, &p, static_cast<long>(key_len)));
    if (ec) {
        bssl::UniquePtr<EVP_PKEY> ec_pkey(EVP_PKEY_new());
        if (ec_pkey && EVP_PKEY_set1_EC_KEY(ec_pkey.get(), ec.get())) return ec_pkey;
    }

    p = key_buf;
    bssl::UniquePtr<RSA> rsa(d2i_RSAPrivateKey(nullptr, &p, static_cast<long>(key_len)));
    if (rsa) {
        bssl::UniquePtr<EVP_PKEY> rsa_pkey(EVP_PKEY_new());
        if (rsa_pkey && EVP_PKEY_set1_RSA(rsa_pkey.get(), rsa.get())) return rsa_pkey;
    }

    return nullptr;
}

static bool parseHexDigestProperty(const std::string& value, std::vector<uint8_t>* out) {
    if (!out || value.size() != 64) {
        return false;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out->clear();
    out->reserve(32);
    for (size_t i = 0; i < value.size(); i += 2) {
        int hi = nibble(value[i]);
        int lo = nibble(value[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out->size() == 32;
}

static bool isAllZeroDigest(const std::vector<uint8_t>& v) {
    if (v.empty()) return true;
    for (uint8_t b : v) {
        if (b != 0) return false;
    }
    return true;
}

static bool readBootDigestProperty(const char* prop_name, std::vector<uint8_t>* out) {
    if (!prop_name || !out) return false;
    const std::string value = android::base::GetProperty(prop_name, "");
    if (!parseHexDigestProperty(value, out)) return false;
    if (isAllZeroDigest(*out)) return false;
    return true;
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

static bool replaceRootOfTrustInTeeEnforced(const std::vector<uint8_t>& tee_enforced_der,
                                            const std::vector<uint8_t>& boot_key,
                                            const std::vector<uint8_t>& boot_hash,
                                            std::vector<uint8_t>* out) {
    if (!out || tee_enforced_der.empty() || boot_key.size() != 32 || boot_hash.size() != 32) {
        return false;
    }

    size_t seq_total = 0, seq_hdr = 0;
    uint32_t seq_tag = 0;
    bool seq_ctx = false;
    if (!parseOneDerElement(tee_enforced_der.data(), tee_enforced_der.size(), &seq_total, &seq_hdr,
                            &seq_tag, &seq_ctx)) {
        return false;
    }
    (void)seq_tag;
    (void)seq_ctx;
    if (seq_total != tee_enforced_der.size() || tee_enforced_der[0] != 0x30) {
        return false;
    }

    const uint8_t* items = tee_enforced_der.data() + seq_hdr;
    size_t items_len = tee_enforced_der.size() - seq_hdr;
    size_t pos = 0;
    std::vector<uint8_t> rebuilt_items;
    rebuilt_items.reserve(items_len + 128);
    while (pos < items_len) {
        size_t el_total = 0, el_hdr = 0;
        uint32_t tag_no = 0;
        bool is_ctx = false;
        if (!parseOneDerElement(items + pos, items_len - pos, &el_total, &el_hdr, &tag_no, &is_ctx)) {
            return false;
        }
        if (!(is_ctx && tag_no == 704)) {
            rebuilt_items.insert(rebuilt_items.end(), items + pos, items + pos + el_total);
        }
        pos += el_total;
    }

    const auto vbk = makeDerTlv(0x04, boot_key);
    // deviceLocked = true (locked)
    const std::vector<uint8_t> locked = {0x01, 0x01, 0xff};
    const std::vector<uint8_t> verified = {0x0A, 0x01, 0x00};  // VerifiedBootState = Verified(0)
    const auto vbh = makeDerTlv(0x04, boot_hash);

    std::vector<uint8_t> rot_value;
    rot_value.reserve(vbk.size() + locked.size() + verified.size() + vbh.size() + 8);
    rot_value.insert(rot_value.end(), vbk.begin(), vbk.end());
    rot_value.insert(rot_value.end(), locked.begin(), locked.end());
    rot_value.insert(rot_value.end(), verified.begin(), verified.end());
    rot_value.insert(rot_value.end(), vbh.begin(), vbh.end());
    const auto rot_seq = makeDerTlv(0x30, rot_value);

    std::vector<uint8_t> rot_tagged;
    rot_tagged.reserve(3 + 5 + rot_seq.size());
    rot_tagged.push_back(0xBF);  // [704] EXPLICIT
    rot_tagged.push_back(0x85);
    rot_tagged.push_back(0x40);
    appendDerLength(&rot_tagged, rot_seq.size());
    rot_tagged.insert(rot_tagged.end(), rot_seq.begin(), rot_seq.end());
    rebuilt_items.insert(rebuilt_items.end(), rot_tagged.begin(), rot_tagged.end());

    *out = makeDerTlv(0x30, rebuilt_items);
    return true;
}

static std::vector<uint8_t> makeExplicitContextTlv(uint32_t tag_no, const std::vector<uint8_t>& val) {
    std::vector<uint8_t> out;
    if (tag_no < 31) {
        out.push_back(static_cast<uint8_t>(0xA0 | tag_no));
    } else {
        out.push_back(0xBF);
        if (tag_no < 128) {
            out.push_back(static_cast<uint8_t>(tag_no));
        } else {
            out.push_back(static_cast<uint8_t>((tag_no >> 7) | 0x80));
            out.push_back(static_cast<uint8_t>(tag_no & 0x7F));
        }
    }
    appendDerLength(&out, val.size());
    out.insert(out.end(), val.begin(), val.end());
    return out;
}

static constexpr const char* kHarvestFile = "/data/system/keystore_compat/harvested.json";
static constexpr const char* kLegacyHarvestFile = "/data/system/tee_simulator/harvested.json";

static bool hexStringToBytes(const std::string& hex, std::vector<uint8_t>* out) {
    if (hex.length() % 2 != 0) return false;
    out->clear();
    out->reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        char buf[3] = { hex[i], hex[i+1], '\0' };
        char* end = nullptr;
        unsigned long byte = strtoul(buf, &end, 16);
        if (end != buf + 2) return false;
        out->push_back(static_cast<uint8_t>(byte));
    }
    return true;
}

static std::string bytesToHexString(const std::vector<uint8_t>& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        hex.push_back(digits[(b >> 4) & 0x0F]);
        hex.push_back(digits[b & 0x0F]);
    }
    return hex;
}

static bool loadHarvestedBootFields(std::vector<uint8_t>* out_key, std::vector<uint8_t>* out_hash) {
    if (!out_key || !out_hash) return false;
    std::ifstream file(kHarvestFile);
    if (!file.is_open()) {
        file.open(kLegacyHarvestFile);
        if (!file.is_open()) return false;
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    auto extractField = [&content](const std::string& key) -> std::string {
        std::string pattern = "\"" + key + "\":";
        size_t pos = content.find(pattern);
        if (pos == std::string::npos) return "";
        pos += pattern.length();
        while (pos < content.length() && (content[pos] == ' ' || content[pos] == '"')) pos++;
        size_t end = content.find_first_of("\",\n}", pos);
        if (end == std::string::npos) return "";
        return content.substr(pos, end - pos);
    };

    std::string key_hex = extractField("verifiedBootKey");
    std::string hash_hex = extractField("verifiedBootHash");
    if (key_hex.length() == 64 && hash_hex.length() == 64) {
        std::vector<uint8_t> k, h;
        if (hexStringToBytes(key_hex, &k) && hexStringToBytes(hash_hex, &h) &&
            !isAllZeroDigest(k) && !isAllZeroDigest(h)) {
            *out_key = std::move(k);
            *out_hash = std::move(h);
            return true;
        }
    }
    return false;
}

static void saveHarvestedBootFields(const std::vector<uint8_t>& key, const std::vector<uint8_t>& hash) {
    if (key.size() != 32 || hash.size() != 32 || isAllZeroDigest(key) || isAllZeroDigest(hash)) {
        return;
    }
    std::ifstream check(kHarvestFile);
    if (check.is_open()) {
        check.close();
        return;
    }
    std::ofstream out(kHarvestFile, std::ios::trunc);
    if (out.is_open()) {
        out << "{\n";
        out << "  \"verifiedBootKey\": \"" << bytesToHexString(key) << "\",\n";
        out << "  \"verifiedBootHash\": \"" << bytesToHexString(hash) << "\",\n";
        out << "  \"deviceLocked\": true,\n";
        out << "  \"verifiedBootState\": \"VERIFIED\"\n";
        out << "}\n";
        out.close();
        chmod(kHarvestFile, 0644);
        ALOGI("saveHarvestedBootFields: saved frozen boot fields to %s", kHarvestFile);
    }
}

static bool extractRootOfTrustBootFields(const std::vector<uint8_t>& tee_enforced_der,
                                         std::vector<uint8_t>* out_boot_key,
                                         std::vector<uint8_t>* out_boot_hash) {
    if (!out_boot_key || !out_boot_hash || tee_enforced_der.empty()) {
        return false;
    }
    size_t seq_total = 0, seq_hdr = 0;
    uint32_t seq_tag = 0;
    bool seq_ctx = false;
    if (!parseOneDerElement(tee_enforced_der.data(), tee_enforced_der.size(), &seq_total, &seq_hdr,
                            &seq_tag, &seq_ctx)) {
        return false;
    }
    (void)seq_tag;
    (void)seq_ctx;
    if (seq_total != tee_enforced_der.size() || tee_enforced_der[0] != 0x30) {
        return false;
    }

    const uint8_t* items = tee_enforced_der.data() + seq_hdr;
    size_t items_len = tee_enforced_der.size() - seq_hdr;
    size_t pos = 0;
    while (pos < items_len) {
        size_t el_total = 0, el_hdr = 0;
        uint32_t tag_no = 0;
        bool is_ctx = false;
        if (!parseOneDerElement(items + pos, items_len - pos, &el_total, &el_hdr, &tag_no, &is_ctx)) {
            return false;
        }
        if (is_ctx && tag_no == 704) {
            const uint8_t* tagged = items + pos;
            const uint8_t* rot_der = tagged + el_hdr;
            size_t rot_der_len = el_total - el_hdr;
            size_t rot_total = 0, rot_hdr = 0;
            uint32_t rot_tag = 0;
            bool rot_ctx = false;
            if (!parseOneDerElement(rot_der, rot_der_len, &rot_total, &rot_hdr, &rot_tag, &rot_ctx)) {
                return false;
            }
            (void)rot_tag;
            (void)rot_ctx;
            if (rot_total != rot_der_len || rot_der[0] != 0x30) {
                return false;
            }

            const uint8_t* rot_items = rot_der + rot_hdr;
            size_t rot_items_len = rot_der_len - rot_hdr;
            size_t rpos = 0;
            int idx = 0;
            while (rpos < rot_items_len) {
                size_t f_total = 0, f_hdr = 0;
                uint32_t f_tag = 0;
                bool f_ctx = false;
                if (!parseOneDerElement(rot_items + rpos, rot_items_len - rpos, &f_total, &f_hdr, &f_tag,
                                        &f_ctx)) {
                    return false;
                }
                (void)f_tag;
                (void)f_ctx;
                const uint8_t* f = rot_items + rpos;
                if (idx == 0 && f[0] == 0x04) {
                    out_boot_key->assign(f + f_hdr, f + f_total);
                } else if (idx == 3 && f[0] == 0x04) {
                    out_boot_hash->assign(f + f_hdr, f + f_total);
                }
                rpos += f_total;
                idx++;
            }
            return !out_boot_key->empty() || !out_boot_hash->empty();
        }
        pos += el_total;
    }
    return false;
}

static bool sha256OfBytes(const uint8_t* data, size_t len, std::vector<uint8_t>* out) {
    if (!data || !out) return false;
    out->assign(SHA256_DIGEST_LENGTH, 0);
    return SHA256(data, len, out->data()) != nullptr;
}

static bool deriveStableBootDigestsFromSignerCert(const uint8_t* signing_cert_buf, size_t signing_cert_len,
                                                  std::vector<uint8_t>* out_boot_key,
                                                  std::vector<uint8_t>* out_boot_hash) {
    if (!signing_cert_buf || signing_cert_len == 0) {
        return false;
    }
    const uint8_t* p = signing_cert_buf;
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &p, static_cast<long>(signing_cert_len)));
    if (!cert) return false;

    bssl::UniquePtr<EVP_PKEY> pubkey(X509_get_pubkey(cert.get()));
    if (!pubkey) return false;
    int pub_len = i2d_PUBKEY(pubkey.get(), nullptr);
    if (pub_len <= 0) return false;
    std::vector<uint8_t> pub_der(static_cast<size_t>(pub_len));
    uint8_t* pub_ptr = pub_der.data();
    if (i2d_PUBKEY(pubkey.get(), &pub_ptr) <= 0) return false;

    if (out_boot_key && (out_boot_key->size() != 32 || isAllZeroDigest(*out_boot_key))) {
        if (!sha256OfBytes(pub_der.data(), pub_der.size(), out_boot_key)) return false;
    }

    if (out_boot_hash && (out_boot_hash->size() != 32 || isAllZeroDigest(*out_boot_hash))) {
        std::vector<uint8_t> hash_seed(signing_cert_buf, signing_cert_buf + signing_cert_len);
        static constexpr char kDomain[] = "keystore_compat_vbmeta_digest_v1";
        hash_seed.insert(hash_seed.end(), reinterpret_cast<const uint8_t*>(kDomain),
                         reinterpret_cast<const uint8_t*>(kDomain) + sizeof(kDomain) - 1);
        if (!sha256OfBytes(hash_seed.data(), hash_seed.size(), out_boot_hash)) return false;
    }

    return true;
}

static void resolveVerifiedBootFields(const uint8_t* signing_cert_buf, size_t signing_cert_len,
                                      const std::vector<uint8_t>& tee_enforced_der,
                                      std::vector<uint8_t>* out_key,
                                      std::vector<uint8_t>* out_hash) {
    if (!out_key || !out_hash) return;
    out_key->clear();
    out_hash->clear();

    // 0) First check if frozen boot fields were harvested previously
    loadHarvestedBootFields(out_key, out_hash);

    // 1) ro.boot.vbmeta.digest is the exact device verified boot hash
    if (out_hash->size() != 32 || isAllZeroDigest(*out_hash)) {
        readBootDigestProperty("ro.boot.vbmeta.digest", out_hash);
    }
    if (out_key->size() != 32 || isAllZeroDigest(*out_key)) {
        readBootDigestProperty("ro.boot.vbmeta.public_key_digest", out_key);
    }

    // 2) Original attestation RootOfTrust values
    if ((out_key->size() != 32 || isAllZeroDigest(*out_key) || out_hash->size() != 32 || isAllZeroDigest(*out_hash)) &&
        !tee_enforced_der.empty()) {
        std::vector<uint8_t> old_key, old_hash;
        if (extractRootOfTrustBootFields(tee_enforced_der, &old_key, &old_hash)) {
            if ((out_key->size() != 32 || isAllZeroDigest(*out_key)) && old_key.size() == 32 && !isAllZeroDigest(old_key)) {
                *out_key = std::move(old_key);
            }
            if ((out_hash->size() != 32 || isAllZeroDigest(*out_hash)) && old_hash.size() == 32 && !isAllZeroDigest(old_hash)) {
                *out_hash = std::move(old_hash);
            }
        }
    }

    // 3) Derive stable verifiedBootKey from signer certificate public key
    if (out_key->size() != 32 || isAllZeroDigest(*out_key)) {
        std::vector<uint8_t> derived_key, dummy_hash;
        if (deriveStableBootDigestsFromSignerCert(signing_cert_buf, signing_cert_len, &derived_key, &dummy_hash)) {
            if (derived_key.size() == 32 && !isAllZeroDigest(derived_key)) {
                *out_key = std::move(derived_key);
                ALOGI("resolveVerifiedBootFields: derived verifiedBootKey from signer cert");
            }
        }
    }

    // 4) Fallbacks if still missing
    if (out_key->size() != 32 || isAllZeroDigest(*out_key)) {
        static constexpr char kFallbackKeySeed[] = "keystore_compat_verified_boot_key_seed_v1";
        sha256OfBytes(reinterpret_cast<const uint8_t*>(kFallbackKeySeed), sizeof(kFallbackKeySeed) - 1, out_key);
        ALOGI("resolveVerifiedBootFields: derived verifiedBootKey from fallback domain seed");
    }
    if (out_hash->size() != 32 || isAllZeroDigest(*out_hash)) {
        static constexpr char kFallbackHashSeed[] = "keystore_compat_verified_boot_hash_seed_v1";
        sha256OfBytes(reinterpret_cast<const uint8_t*>(kFallbackHashSeed), sizeof(kFallbackHashSeed) - 1, out_hash);
        ALOGI("resolveVerifiedBootFields: derived verifiedBootHash from fallback domain seed");
    }

    saveHarvestedBootFields(*out_key, *out_hash);
}

static bool patchAttestationRootOfTrust(X509* cert, const uint8_t* signing_cert_buf,
                                        size_t signing_cert_len) {
    if (!cert) return false;

    ASN1_OBJECT* att_oid_obj = OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1);
    if (!att_oid_obj) return false;
    int ext_idx = X509_get_ext_by_OBJ(cert, att_oid_obj, -1);
    ASN1_OBJECT_free(att_oid_obj);
    if (ext_idx < 0) return false;

    X509_EXTENSION* ext = X509_get_ext(cert, ext_idx);
    if (!ext) return false;
    ASN1_OCTET_STRING* ext_data = X509_EXTENSION_get_data(ext);
    if (!ext_data || !ext_data->data || ext_data->length <= 0) return false;

    const uint8_t* p = ext_data->data;
    STACK_OF(ASN1_TYPE)* key_desc = d2i_ASN1_SEQUENCE_ANY(nullptr, &p, ext_data->length);
    if (!key_desc || sk_ASN1_TYPE_num(key_desc) < 8) {
        if (key_desc) {
            sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
        }
        return false;
    }

    ASN1_TYPE* tee_enforced = sk_ASN1_TYPE_value(key_desc, 7);
    if (!tee_enforced) {
        sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
        return false;
    }
    int tee_len = i2d_ASN1_TYPE(tee_enforced, nullptr);
    if (tee_len <= 0) {
        sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
        return false;
    }
    std::vector<uint8_t> tee_buf(static_cast<size_t>(tee_len));
    uint8_t* tee_ptr = tee_buf.data();
    if (i2d_ASN1_TYPE(tee_enforced, &tee_ptr) <= 0) {
        sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
        return false;
    }

    std::vector<uint8_t> boot_key;
    std::vector<uint8_t> boot_hash;
    resolveVerifiedBootFields(signing_cert_buf, signing_cert_len, tee_buf, &boot_key, &boot_hash);

    std::vector<uint8_t> new_tee;
    if (!replaceRootOfTrustInTeeEnforced(tee_buf, boot_key, boot_hash, &new_tee)) {
        ALOGW("patchAttestationRootOfTrust: failed to rebuild teeEnforced RootOfTrust");
        sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
        return false;
    }

    std::vector<uint8_t> key_desc_items;
    for (int i = 0; i < sk_ASN1_TYPE_num(key_desc); ++i) {
        if (i == 7) {
            key_desc_items.insert(key_desc_items.end(), new_tee.begin(), new_tee.end());
            continue;
        }
        ASN1_TYPE* item = sk_ASN1_TYPE_value(key_desc, i);
        if (!item) {
            sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
            return false;
        }
        int n = i2d_ASN1_TYPE(item, nullptr);
        if (n <= 0) {
            sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
            return false;
        }
        std::vector<uint8_t> tmp(static_cast<size_t>(n));
        uint8_t* ptr = tmp.data();
        if (i2d_ASN1_TYPE(item, &ptr) <= 0) {
            sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
            return false;
        }
        key_desc_items.insert(key_desc_items.end(), tmp.begin(), tmp.end());
    }
    sk_ASN1_TYPE_pop_free(key_desc, ASN1_TYPE_free);
    std::vector<uint8_t> new_key_desc = makeDerTlv(0x30, key_desc_items);
    if (ASN1_OCTET_STRING_set(ext_data, new_key_desc.data(), static_cast<int>(new_key_desc.size())) != 1) {
        ALOGW("patchAttestationRootOfTrust: failed to write patched attestation extension");
        return false;
    }
    ALOGI("patchAttestationRootOfTrust: patched verifiedBoot fields (locked=true,state=verified)");
    return true;
}

int resignLeafCertificate(const uint8_t* leaf_cert_buf, size_t leaf_cert_len,
                          const uint8_t* signing_cert_buf, size_t signing_cert_len,
                          const uint8_t* signing_key_buf, size_t signing_key_len,
                          uint8_t* out_cert_buf, size_t out_cert_buf_len) {
    if (!leaf_cert_buf || !signing_cert_buf || !signing_key_buf || !out_cert_buf) {
        ALOGE("resignLeafCertificate: null pointer input");
        return 0;
    }

    const uint8_t* leaf_p = leaf_cert_buf;
    bssl::UniquePtr<X509> leaf(d2i_X509(nullptr, &leaf_p, static_cast<long>(leaf_cert_len)));
    if (!leaf) {
        ALOGE("resignLeafCertificate: failed to parse leaf cert");
        return 0;
    }

    const uint8_t* signer_p = signing_cert_buf;
    bssl::UniquePtr<X509> signing_cert(
            d2i_X509(nullptr, &signer_p, static_cast<long>(signing_cert_len)));
    if (!signing_cert) {
        ALOGE("resignLeafCertificate: failed to parse signing cert");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> signing_key = parseSigningKey(signing_key_buf, signing_key_len);
    if (!signing_key) {
        ALOGE("resignLeafCertificate: failed to parse signing key");
        return 0;
    }

    if (auto e = keystore::setIssuer(leaf.get(), signing_cert.get(), false /* addAuthKeyExt */); e) {
        ALOGE("resignLeafCertificate: setIssuer failed");
        return 0;
    }

    // Align key attestation RootOfTrust semantics with compatibility behavior:
    // force Verified state and locked=true, with boot key/hash from vbmeta properties.
    (void)patchAttestationRootOfTrust(leaf.get(), signing_cert_buf, signing_cert_len);

    if (auto e = keystore::signCert(leaf.get(), signing_key.get()); e) {
        ALOGE("resignLeafCertificate: signCert failed");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> signing_pubkey(X509_get_pubkey(signing_cert.get()));
    if (!signing_pubkey) {
        ALOGE("resignLeafCertificate: failed to get signer pubkey");
        return 0;
    }
    if (X509_verify(leaf.get(), signing_pubkey.get()) != 1) {
        ALOGE("resignLeafCertificate: leaf verification against signer pubkey failed");
        return 0;
    }

    auto encoded_or_error = keystore::encodeCert(leaf.get());
    if (std::holds_alternative<keystore::CertUtilsError>(encoded_or_error)) {
        ALOGE("resignLeafCertificate: encodeCert failed");
        return 0;
    }

    const auto& encoded = std::get<std::vector<uint8_t>>(encoded_or_error);
    if (encoded.size() > out_cert_buf_len) {
        return -static_cast<int>(encoded.size());
    }

    std::copy(encoded.begin(), encoded.end(), out_cert_buf);
    return static_cast<int>(encoded.size());
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

int generateSoftwareAttestedKey(
        int key_type, int rsa_key_size,
        const uint8_t* challenge, size_t challenge_len,
        const uint8_t* signing_cert_buf, size_t signing_cert_len,
        const uint8_t* signing_key_buf, size_t signing_key_len,
        int is_attest_key,
        uint8_t* out_privkey_buf, size_t out_privkey_buf_len,
        size_t* out_privkey_len,
        uint8_t* out_cert_buf, size_t out_cert_buf_len) {
    if (!signing_cert_buf || !signing_key_buf || !out_privkey_buf || !out_privkey_len || !out_cert_buf) {
        ALOGE("generateSoftwareAttestedKey: null pointer input");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (!pkey) return 0;

    int key_algorithm_val = 3; // 3 = EC, 1 = RSA
    int key_size_val = 256;

    if (key_type == 1) { // RSA
        key_algorithm_val = 1;
        key_size_val = (rsa_key_size > 0) ? rsa_key_size : 2048;
        bssl::UniquePtr<RSA> rsa(RSA_new());
        bssl::UniquePtr<BIGNUM> e(BN_new());
        if (!rsa || !e || !BN_set_word(e.get(), RSA_F4) ||
            !RSA_generate_key_ex(rsa.get(), key_size_val, e.get(), nullptr)) {
            ALOGE("generateSoftwareAttestedKey: RSA generation failed");
            return 0;
        }
        if (!EVP_PKEY_set1_RSA(pkey.get(), rsa.get())) return 0;
    } else { // EC P-256
        bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
        if (!ec || !EC_KEY_generate_key(ec.get())) {
            ALOGE("generateSoftwareAttestedKey: EC generation failed");
            return 0;
        }
        if (!EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get())) return 0;
    }

    std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> p8(
            EVP_PKEY2PKCS8(pkey.get()), PKCS8_PRIV_KEY_INFO_free);
    if (!p8) {
        ALOGE("generateSoftwareAttestedKey: EVP_PKEY2PKCS8 failed");
        return 0;
    }
    int p8_len = i2d_PKCS8_PRIV_KEY_INFO(p8.get(), nullptr);
    if (p8_len <= 0 || static_cast<size_t>(p8_len) > out_privkey_buf_len) {
        ALOGE("generateSoftwareAttestedKey: PKCS8 buffer too small or encode failed");
        return 0;
    }
    uint8_t* p8_ptr = out_privkey_buf;
    if (i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &p8_ptr) <= 0) {
        ALOGE("generateSoftwareAttestedKey: i2d_PKCS8_PRIV_KEY_INFO failed");
        return 0;
    }
    *out_privkey_len = static_cast<size_t>(p8_len);

    const uint8_t* signer_p = signing_cert_buf;
    bssl::UniquePtr<X509> signing_cert(d2i_X509(nullptr, &signer_p, static_cast<long>(signing_cert_len)));
    if (!signing_cert) {
        ALOGE("generateSoftwareAttestedKey: failed to parse signing cert");
        return 0;
    }
    bssl::UniquePtr<EVP_PKEY> signer_pkey = parseSigningKey(signing_key_buf, signing_key_len);
    if (!signer_pkey) {
        ALOGE("generateSoftwareAttestedKey: failed to parse signing key");
        return 0;
    }

    bssl::UniquePtr<X509> cert(X509_new());
    if (!cert) return 0;
    if (!X509_set_version(cert.get(), 2)) return 0;

    bssl::UniquePtr<BIGNUM> serial_bn(BN_new());
    if (!serial_bn || !BN_pseudo_rand(serial_bn.get(), 64, 0, 0)) return 0;
    bssl::UniquePtr<ASN1_INTEGER> serial(BN_to_ASN1_INTEGER(serial_bn.get(), nullptr));
    if (!serial || !X509_set_serialNumber(cert.get(), serial.get())) return 0;

    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 315360000L);

    if (!X509_set_pubkey(cert.get(), pkey.get())) return 0;
    if (!X509_set_issuer_name(cert.get(), X509_get_subject_name(signing_cert.get()))) return 0;

    X509_NAME* subj = X509_get_subject_name(cert.get());
    if (!subj || !X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                                             reinterpret_cast<const uint8_t*>("Android Keystore Key"),
                                             -1, -1, 0)) {
        return 0;
    }

    std::vector<uint8_t> boot_key, boot_hash;
    resolveVerifiedBootFields(signing_cert_buf, signing_cert_len, {}, &boot_key, &boot_hash);

    std::vector<uint8_t> rot_val;
    rot_val.insert(rot_val.end(), makeDerTlv(0x04, boot_key).begin(), makeDerTlv(0x04, boot_key).end());
    const std::vector<uint8_t> locked_der = {0x01, 0x01, 0xff};
    rot_val.insert(rot_val.end(), locked_der.begin(), locked_der.end());
    const std::vector<uint8_t> verified_der = {0x0A, 0x01, 0x00};
    rot_val.insert(rot_val.end(), verified_der.begin(), verified_der.end());
    rot_val.insert(rot_val.end(), makeDerTlv(0x04, boot_hash).begin(), makeDerTlv(0x04, boot_hash).end());
    std::vector<uint8_t> rot_seq = makeDerTlv(0x30, rot_val);

    std::vector<uint8_t> tee_items;

    std::vector<uint8_t> purpose_set_val;
    const std::vector<uint8_t> p_sign = {0x02, 0x01, 0x02};
    const std::vector<uint8_t> p_verify = {0x02, 0x01, 0x03};
    purpose_set_val.insert(purpose_set_val.end(), p_sign.begin(), p_sign.end());
    purpose_set_val.insert(purpose_set_val.end(), p_verify.begin(), p_verify.end());
    if (is_attest_key) {
        const std::vector<uint8_t> p_attest = {0x02, 0x01, 0x07};
        purpose_set_val.insert(purpose_set_val.end(), p_attest.begin(), p_attest.end());
    }
    std::vector<uint8_t> purpose_set = makeDerTlv(0x31, purpose_set_val);
    auto tag1 = makeExplicitContextTlv(1, purpose_set);
    tee_items.insert(tee_items.end(), tag1.begin(), tag1.end());

    std::vector<uint8_t> alg_int = {0x02, 0x01, static_cast<uint8_t>(key_algorithm_val)};
    auto tag2 = makeExplicitContextTlv(2, alg_int);
    tee_items.insert(tee_items.end(), tag2.begin(), tag2.end());

    std::vector<uint8_t> ks_val;
    if (key_size_val < 128) {
        ks_val = {0x02, 0x01, static_cast<uint8_t>(key_size_val)};
    } else {
        ks_val = {0x02, 0x02, static_cast<uint8_t>(key_size_val >> 8), static_cast<uint8_t>(key_size_val & 0xFF)};
    }
    auto tag3 = makeExplicitContextTlv(3, ks_val);
    tee_items.insert(tee_items.end(), tag3.begin(), tag3.end());

    std::vector<uint8_t> dig_set_val = {0x02, 0x01, 0x04};
    std::vector<uint8_t> dig_set = makeDerTlv(0x31, dig_set_val);
    auto tag5 = makeExplicitContextTlv(5, dig_set);
    tee_items.insert(tee_items.end(), tag5.begin(), tag5.end());

    std::vector<uint8_t> null_val = {0x05, 0x00};
    auto tag503 = makeExplicitContextTlv(503, null_val);
    tee_items.insert(tee_items.end(), tag503.begin(), tag503.end());

    std::vector<uint8_t> orig_val = {0x02, 0x01, 0x00};
    auto tag702 = makeExplicitContextTlv(702, orig_val);
    tee_items.insert(tee_items.end(), tag702.begin(), tag702.end());

    auto tag704 = makeExplicitContextTlv(704, rot_seq);
    tee_items.insert(tee_items.end(), tag704.begin(), tag704.end());

    std::vector<uint8_t> os_ver_val = {0x02, 0x03, 0x02, 0x71, 0x00};
    auto tag705 = makeExplicitContextTlv(705, os_ver_val);
    tee_items.insert(tee_items.end(), tag705.begin(), tag705.end());

    std::vector<uint8_t> os_patch_val = {0x02, 0x03, 0x03, 0x17, 0x6E};
    auto tag706 = makeExplicitContextTlv(706, os_patch_val);
    tee_items.insert(tee_items.end(), tag706.begin(), tag706.end());

    std::vector<uint8_t> tee_enforced_seq = makeDerTlv(0x30, tee_items);

    std::vector<uint8_t> kd_items;
    const std::vector<uint8_t> att_ver = {0x02, 0x02, 0x01, 0x2C};
    const std::vector<uint8_t> att_sec = {0x0A, 0x01, 0x01};
    const std::vector<uint8_t> km_ver = {0x02, 0x02, 0x01, 0x2C};
    const std::vector<uint8_t> km_sec = {0x0A, 0x01, 0x01};
    std::vector<uint8_t> chal_oct = makeDerTlv(0x04, std::vector<uint8_t>(challenge, challenge + challenge_len));
    const std::vector<uint8_t> uniq_id = {0x04, 0x00};
    const std::vector<uint8_t> sw_enforced = {0x30, 0x00};

    kd_items.insert(kd_items.end(), att_ver.begin(), att_ver.end());
    kd_items.insert(kd_items.end(), att_sec.begin(), att_sec.end());
    kd_items.insert(kd_items.end(), km_ver.begin(), km_ver.end());
    kd_items.insert(kd_items.end(), km_sec.begin(), km_sec.end());
    kd_items.insert(kd_items.end(), chal_oct.begin(), chal_oct.end());
    kd_items.insert(kd_items.end(), uniq_id.begin(), uniq_id.end());
    kd_items.insert(kd_items.end(), sw_enforced.begin(), sw_enforced.end());
    kd_items.insert(kd_items.end(), tee_enforced_seq.begin(), tee_enforced_seq.end());

    std::vector<uint8_t> kd_seq = makeDerTlv(0x30, kd_items);

    bssl::UniquePtr<ASN1_OCTET_STRING> ext_data(ASN1_OCTET_STRING_new());
    if (!ext_data || ASN1_OCTET_STRING_set(ext_data.get(), kd_seq.data(), static_cast<int>(kd_seq.size())) != 1) {
        return 0;
    }
    bssl::UniquePtr<ASN1_OBJECT> ext_oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1));
    if (!ext_oid) return 0;
    bssl::UniquePtr<X509_EXTENSION> ext(X509_EXTENSION_create_by_OBJ(nullptr, ext_oid.get(), 0, ext_data.get()));
    if (!ext || !X509_add_ext(cert.get(), ext.get(), -1)) return 0;

    if (auto e = keystore::signCert(cert.get(), signer_pkey.get()); e) {
        ALOGE("generateSoftwareAttestedKey: signCert failed");
        return 0;
    }

    bssl::UniquePtr<EVP_PKEY> signer_pubkey(X509_get_pubkey(signing_cert.get()));
    if (!signer_pubkey || X509_verify(cert.get(), signer_pubkey.get()) != 1) {
        ALOGE("generateSoftwareAttestedKey: verification failed");
        return 0;
    }

    auto encoded_or_error = keystore::encodeCert(cert.get());
    if (std::holds_alternative<keystore::CertUtilsError>(encoded_or_error)) {
        return 0;
    }
    const auto& encoded = std::get<std::vector<uint8_t>>(encoded_or_error);
    if (encoded.size() > out_cert_buf_len) {
        return -static_cast<int>(encoded.size());
    }
    memcpy(out_cert_buf, encoded.data(), encoded.size());
    return static_cast<int>(encoded.size());
}
