#ifndef GATEWAYENCLAVE_T_H__
#define GATEWAYENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_eid.h"
#include "datatypes.h"
#include "../Include/dh_session_protocol.h"
#include "sgx_trts.h"
#include "sgx_report.h"
#include "../Include/wasm_request.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t test_create_session(sgx_enclave_id_t wasm_vm_enclave_id);
uint32_t test_close_session(sgx_enclave_id_t wasm_vm_encalve_id);
uint32_t session_request(sgx_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id);
uint32_t exchange_report(sgx_dh_dcap_msg2_t* dh_msg2, sgx_dh_dcap_msg3_t* dh_msg3, uint32_t session_id);
uint32_t generate_response(secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t* resp_message_size, uint32_t session_id);
uint32_t end_session(uint32_t session_id);

sgx_status_t SGX_CDECL session_request_ocall(uint32_t* retval, sgx_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id, sgx_enclave_id_t wasm_vm_enclave_id);
sgx_status_t SGX_CDECL exchange_report_ocall(uint32_t* retval, sgx_dh_dcap_msg2_t* dh_msg2, sgx_dh_dcap_msg3_t* dh_msg3, uint32_t session_id, sgx_enclave_id_t wasm_vm_enclave_id);
sgx_status_t SGX_CDECL send_request_ocall(uint32_t* retval, uint32_t session_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size, sgx_enclave_id_t wasm_vm_enclave_id);
sgx_status_t SGX_CDECL end_session_ocall(uint32_t* retval, uint32_t session_id, sgx_enclave_id_t wasm_vm_enclave_id);
sgx_status_t SGX_CDECL ecdsa_quote_verification_ocall(uint32_t* retval, uint8_t* quote_buffer, uint32_t quote_size);
sgx_status_t SGX_CDECL ecdsa_quote_generation_ocall(uint32_t* retval, uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote);
sgx_status_t SGX_CDECL ecdsa_get_qe_target_info_ocall(uint32_t* retval, sgx_target_info_t* qe_target_info);
sgx_status_t SGX_CDECL ocall_print(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
