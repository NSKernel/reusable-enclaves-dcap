#ifndef WASM_REQUEST_H
#define WASM_REQUEST_H

#include <stdint.h>

typedef struct _wasm_exec_request_t {
	uint64_t size;
	uint8_t mac[16];
	uint8_t payload[];
} __attribute__((__packed__)) wasm_exec_request_t;

#endif