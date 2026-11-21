#include "BridgeCrypto.h"
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

void *mb_spake_new(int receiver) {
    static const uint8_t a[] = "micbridge/2 receiver";
    static const uint8_t b[] = "micbridge/2 sender";
    return receiver ? SPAKE2_CTX_new(spake2_role_alice, a, sizeof(a) - 1, b, sizeof(b) - 1)
                    : SPAKE2_CTX_new(spake2_role_bob, b, sizeof(b) - 1, a, sizeof(a) - 1);
}

int mb_spake_start(void *ctx, const uint8_t pin[4], uint8_t message[32]) {
    size_t n = 0;
    return SPAKE2_generate_msg(ctx, message, &n, 32, pin, 4) && n == 32;
}

int mb_spake_finish(void *ctx, const uint8_t message[32], uint8_t secret[64]) {
    size_t n = 0;
    return SPAKE2_process_msg(ctx, secret, &n, 64, message, 32) && n == 64;
}

void mb_spake_free(void *ctx) { SPAKE2_CTX_free(ctx); }

size_t mb_make_identity(uint8_t key[97], uint8_t *certificate, size_t capacity) {
    size_t result = 0;
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EVP_PKEY *pkey = EVP_PKEY_new();
    X509 *cert = X509_new();
    uint8_t serial_bytes[16];
    BIGNUM *serial = NULL;
    static const uint8_t name[] = "MicBridge";
    if (!ec || !pkey || !cert || !EC_KEY_generate_key(ec) ||
        !EVP_PKEY_set1_EC_KEY(pkey, ec) || !RAND_bytes(serial_bytes, sizeof(serial_bytes))) goto done;
    serial = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
    X509_NAME *subject = X509_get_subject_name(cert);
    if (!serial || !subject || !X509_set_version(cert, 2) ||
        !BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(cert)) ||
        !X509_gmtime_adj(X509_getm_notBefore(cert), -300) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert), 10L * 365 * 24 * 60 * 60) ||
        !X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, name, sizeof(name) - 1, -1, 0) ||
        !X509_set_issuer_name(cert, subject) || !X509_set_pubkey(cert, pkey) ||
        !X509_sign(cert, pkey, EVP_sha256())) goto done;
    int n = i2d_X509(cert, NULL);
    if (n <= 0 || (size_t)n > capacity ||
        EC_POINT_point2oct(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(ec),
                          POINT_CONVERSION_UNCOMPRESSED, key, 65, NULL) != 65 ||
        !BN_bn2bin_padded(key + 65, 32, EC_KEY_get0_private_key(ec)) ||
        i2d_X509(cert, &certificate) != n) goto done;
    result = (size_t)n;
done:
    if (!result) OPENSSL_cleanse(key, 97);
    BN_free(serial);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec);
    return result;
}
