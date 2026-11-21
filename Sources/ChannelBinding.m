#import "BridgeCrypto.h"
#include <string.h>

int mb_channel_binding(sec_protocol_metadata_t metadata, uint8_t out[32]) {
    if (sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata) != tls_protocol_version_TLSv13 ||
        sec_protocol_metadata_get_early_data_accepted(metadata)) return 0;
    // The copy variant was added in macOS 15.5; keep building with older SDKs.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    const char *alpn = sec_protocol_metadata_get_negotiated_protocol(metadata);
#pragma clang diagnostic pop
    if (!alpn || strcmp(alpn, "micbridge/2") != 0) return 0;
    static const char label[] = "EXPORTER-MicBridge-v2";
    dispatch_data_t secret = sec_protocol_metadata_create_secret(metadata, sizeof(label) - 1, label, 32);
    if (!secret) return 0;
    const void *bytes = NULL;
    size_t size = 0;
    __attribute__((objc_precise_lifetime)) dispatch_data_t mapped = dispatch_data_create_map(secret, &bytes, &size);
    if (!mapped || size != 32) return 0;
    memcpy(out, bytes, size);
    return 1;
}
