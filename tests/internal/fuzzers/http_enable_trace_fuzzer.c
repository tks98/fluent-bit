#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <msgpack.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config.h>
#include <trace.h>  

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mk_request_t request;
    struct flb_hs hs;
    struct flb_config config;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    flb_sds_t input_name;

    if (size < 1) {
        return 0;
    }

    flb_config_init(&config);
    hs.config = &config;

    input_name = flb_sds_create_len((const char *)data, size);
    if (!input_name) {
        return 0;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    http_enable_trace(&request, &hs, input_name, flb_sds_len(input_name), &mp_pck);

    flb_sds_destroy(input_name);
    msgpack_sbuffer_destroy(&mp_sbuf);
    flb_config_exit(&config);

    return 0;
}