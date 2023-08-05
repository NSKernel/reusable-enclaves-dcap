#ifndef GATEWAYENCLAVE_U_H__
#define GATEWAYENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

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

#ifndef SESSION_REQUEST_OCALL_DEFINED__
#define SESSION_REQUEST_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, session_request_ocall, (sgx_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id, sgx_enclave_id_t wasm_vm_enclave_id));
#endif
#ifndef EXCHANGE_REPORT_OCALL_DEFINED__
#define EXCHANGE_REPORT_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (sgx_dh_dcap_msg2_t* dh_msg2, sgx_dh_dcap_msg3_t* dh_msg3, uint32_t session_id, sgx_enclave_id_t wasm_vm_enclave_id));
#endif
#ifndef SEND_REQUEST_OCALL_DEFINED__
#define SEND_REQUEST_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, send_request_ocall, (uint32_t session_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size, sgx_enclave_id_t wasm_vm_enclave_id));
#endif
#ifndef END_SESSION_OCALL_DEFINED__
#define END_SESSION_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, end_session_ocall, (uint32_t session_id, sgx_enclave_id_t wasm_vm_enclave_id));
#endif
#ifndef ECDSA_QUOTE_VERIFICATION_OCALL_DEFINED__
#define ECDSA_QUOTE_VERIFICATION_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, ecdsa_quote_verification_ocall, (uint8_t* quote_buffer, uint32_t quote_size));
#endif
#ifndef ECDSA_QUOTE_GENERATION_OCALL_DEFINED__
#define ECDSA_QUOTE_GENERATION_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, ecdsa_quote_generation_ocall, (uint32_t* quote_size, sgx_report_t* app_report, uint8_t* quote));
#endif
#ifndef ECDSA_GET_QE_TARGET_INFO_OCALL_DEFINED__
#define ECDSA_GET_QE_TARGET_INFO_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, ecdsa_get_qe_target_info_ocall, (sgx_target_info_t* qe_target_info));
#endif
#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif

sgx_status_t test_create_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t wasm_vm_enclave_id);
sgx_status_t test_close_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t wasm_vm_encalve_id);
sgx_status_t session_request(sgx_enclave_id_t eid, uint32_t* retval, sgx_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id);
sgx_status_t exchange_report(sgx_enclave_id_t eid, uint32_t* retval, sgx_dh_dcap_msg2_t* dh_msg2, sgx_dh_dcap_msg3_t* dh_msg3, uint32_t session_id);
sgx_status_t generate_response(sgx_enclave_id_t eid, uint32_t* retval, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t* resp_message_size, uint32_t session_id);
sgx_status_t end_session(sgx_enclave_id_t eid, uint32_t* retval, uint32_t session_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
