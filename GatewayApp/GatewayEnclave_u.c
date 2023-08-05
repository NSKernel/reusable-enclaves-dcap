#include "GatewayEnclave_u.h"
#include <errno.h>

typedef struct ms_test_create_session_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_wasm_vm_enclave_id;
} ms_test_create_session_t;

typedef struct ms_test_close_session_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_wasm_vm_encalve_id;
} ms_test_close_session_t;

typedef struct ms_session_request_t {
	uint32_t ms_retval;
	sgx_dh_dcap_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_t;

typedef struct ms_exchange_report_t {
	uint32_t ms_retval;
	sgx_dh_dcap_msg2_t* ms_dh_msg2;
	sgx_dh_dcap_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_t;

typedef struct ms_generate_response_t {
	uint32_t ms_retval;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t* ms_resp_message_size;
	uint32_t ms_session_id;
} ms_generate_response_t;

typedef struct ms_end_session_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
} ms_end_session_t;

typedef struct ms_session_request_ocall_t {
	uint32_t ms_retval;
	sgx_dh_dcap_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
	sgx_enclave_id_t ms_wasm_vm_enclave_id;
} ms_session_request_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	uint32_t ms_retval;
	sgx_dh_dcap_msg2_t* ms_dh_msg2;
	sgx_dh_dcap_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
	sgx_enclave_id_t ms_wasm_vm_enclave_id;
} ms_exchange_report_ocall_t;

typedef struct ms_send_request_ocall_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
	sgx_enclave_id_t ms_wasm_vm_enclave_id;
} ms_send_request_ocall_t;

typedef struct ms_end_session_ocall_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
	sgx_enclave_id_t ms_wasm_vm_enclave_id;
} ms_end_session_ocall_t;

typedef struct ms_ecdsa_quote_verification_ocall_t {
	uint32_t ms_retval;
	uint8_t* ms_quote_buffer;
	uint32_t ms_quote_size;
} ms_ecdsa_quote_verification_ocall_t;

typedef struct ms_ecdsa_quote_generation_ocall_t {
	uint32_t ms_retval;
	uint32_t* ms_quote_size;
	sgx_report_t* ms_app_report;
	uint8_t* ms_quote;
} ms_ecdsa_quote_generation_ocall_t;

typedef struct ms_ecdsa_get_qe_target_info_ocall_t {
	uint32_t ms_retval;
	sgx_target_info_t* ms_qe_target_info;
} ms_ecdsa_get_qe_target_info_ocall_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL GatewayEnclave_session_request_ocall(void* pms)
{
	ms_session_request_ocall_t* ms = SGX_CAST(ms_session_request_ocall_t*, pms);
	ms->ms_retval = session_request_ocall(ms->ms_dh_msg1, ms->ms_session_id, ms->ms_wasm_vm_enclave_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL GatewayEnclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_dh_msg2, ms->ms_dh_msg3, ms->ms_session_id, ms->ms_wasm_vm_enclave_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL GatewayEnclave_send_request_ocall(void* pms)
{
	ms_send_request_ocall_t* ms = SGX_CAST(ms_send_request_ocall_t*, pms);
	ms->ms_retval = send_request_ocall(ms->ms_session_id, ms->ms_req_message, ms->ms_req_message_size, ms->ms_max_payload_size, ms->ms_resp_message, ms->ms_resp_message_size, ms->ms_wasm_vm_enclave_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL GatewayEnclave_end_session_ocall(void* pms)
{
	ms_end_session_ocall_t* ms = SGX_CAST(ms_end_session_ocall_t*, pms);
	ms->ms_retval = end_session_ocall(ms->ms_session_id, ms->ms_wasm_vm_enclave_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL GatewayEnclave_ecdsa_quote_verification_ocall(void* pms)
{
	ms_ecdsa_quote_verification_ocall_t* ms = SGX_CAST(ms_ecdsa_quote_verification_ocall_t*, pms);
	ms->ms_retval = ecdsa_quote_verification_ocall(ms->ms_quote_buffer, ms->ms_quote_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL GatewayEnclave_ecdsa_quote_generation_ocall(void* pms)
{
	ms_ecdsa_quote_generation_ocall_t* ms = SGX_CAST(ms_ecdsa_quote_generation_ocall_t*, pms);
	ms->ms_retval = ecdsa_quote_generation_ocall(ms->ms_quote_size, ms->ms_app_report, ms->ms_quote);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL GatewayEnclave_ecdsa_get_qe_target_info_ocall(void* pms)
{
	ms_ecdsa_get_qe_target_info_ocall_t* ms = SGX_CAST(ms_ecdsa_get_qe_target_info_ocall_t*, pms);
	ms->ms_retval = ecdsa_get_qe_target_info_ocall(ms->ms_qe_target_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL GatewayEnclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[8];
} ocall_table_GatewayEnclave = {
	8,
	{
		(void*)GatewayEnclave_session_request_ocall,
		(void*)GatewayEnclave_exchange_report_ocall,
		(void*)GatewayEnclave_send_request_ocall,
		(void*)GatewayEnclave_end_session_ocall,
		(void*)GatewayEnclave_ecdsa_quote_verification_ocall,
		(void*)GatewayEnclave_ecdsa_quote_generation_ocall,
		(void*)GatewayEnclave_ecdsa_get_qe_target_info_ocall,
		(void*)GatewayEnclave_ocall_print,
	}
};
sgx_status_t test_create_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t wasm_vm_enclave_id)
{
	sgx_status_t status;
	ms_test_create_session_t ms;
	ms.ms_wasm_vm_enclave_id = wasm_vm_enclave_id;
	status = sgx_ecall(eid, 0, &ocall_table_GatewayEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t test_close_session(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t wasm_vm_encalve_id)
{
	sgx_status_t status;
	ms_test_close_session_t ms;
	ms.ms_wasm_vm_encalve_id = wasm_vm_encalve_id;
	status = sgx_ecall(eid, 1, &ocall_table_GatewayEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t session_request(sgx_enclave_id_t eid, uint32_t* retval, sgx_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id)
{
	sgx_status_t status;
	ms_session_request_t ms;
	ms.ms_dh_msg1 = dh_msg1;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 2, &ocall_table_GatewayEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t exchange_report(sgx_enclave_id_t eid, uint32_t* retval, sgx_dh_dcap_msg2_t* dh_msg2, sgx_dh_dcap_msg3_t* dh_msg3, uint32_t session_id)
{
	sgx_status_t status;
	ms_exchange_report_t ms;
	ms.ms_dh_msg2 = dh_msg2;
	ms.ms_dh_msg3 = dh_msg3;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 3, &ocall_table_GatewayEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t generate_response(sgx_enclave_id_t eid, uint32_t* retval, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t* resp_message_size, uint32_t session_id)
{
	sgx_status_t status;
	ms_generate_response_t ms;
	ms.ms_req_message = req_message;
	ms.ms_req_message_size = req_message_size;
	ms.ms_max_payload_size = max_payload_size;
	ms.ms_resp_message = resp_message;
	ms.ms_resp_message_size = resp_message_size;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 4, &ocall_table_GatewayEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t end_session(sgx_enclave_id_t eid, uint32_t* retval, uint32_t session_id)
{
	sgx_status_t status;
	ms_end_session_t ms;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 5, &ocall_table_GatewayEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

