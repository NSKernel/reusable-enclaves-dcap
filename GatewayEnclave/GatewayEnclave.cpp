/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// Enclave1.cpp : Defines the exported functions for the .so application
#include "sgx_eid.h"
#include "GatewayEnclave_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"

#include "sgx_utils.h"
#include <map>
#define UNUSED(val) (void)(val)

#define WASM_VM_PRODID 1
#define FILE_SIZE 1452

extern int printf(const char* fmt, ...);

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

// This is hardcoded wasm vm enclave's MRSIGNER for demonstration purpose. The content aligns to wasm vm enclave's signing key
sgx_measurement_t g_wasm_vm_mrsigner = {
	{
		0x83, 0xd7, 0x19, 0xe7, 0x7d, 0xea, 0xca, 0x14, 0x70, 0xf6, 0xba, 0xf6, 0x2a, 0x4d, 0x77, 0x43,
		0x03, 0xc8, 0x99, 0xdb, 0x69, 0x02, 0x0f, 0x9c, 0x70, 0xee, 0x1d, 0xfc, 0x08, 0xc7, 0xce, 0x9e
	}
};

#include <assert.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"

/* Function Description:
 *   This is ECALL routine to create ECDH session.
 *   When it succeeds to create ECDH session, the session context is saved in g_session.
 * */
extern "C" uint32_t test_create_session(sgx_enclave_id_t wasm_vm_enclave_id)
{
    dh_session_t* g_session;
    g_session = (dh_session_t *)malloc(sizeof(dh_session_t));
    if(!g_session)
        return MALLOC_ERROR;
    g_src_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(wasm_vm_enclave_id, *g_session));

    return create_session(&g_src_session_info_map.find(wasm_vm_enclave_id)->second, wasm_vm_enclave_id);
}

#include "wasm_request.h"

/* Function Description:
 *   This routine transfers message with ECDH peer
 * */
#define WASM_VM_RESPONSE_MAX_SIZE   2048
uint32_t relay_wasm_file(sgx_enclave_id_t wasm_vm_enclave_id, uint8_t *plain_wasm_buffer, uint64_t wasm_size, uint8_t *exec_response, uint64_t *exec_response_size)
{
    ATTESTATION_STATUS ke_status = SUCCESS;

    // Send
    ke_status = encrypt_to_enclave(&g_src_session_info_map.find(wasm_vm_enclave_id)->second, plain_wasm_buffer,
                                                wasm_size, WASM_VM_RESPONSE_MAX_SIZE, exec_response, exec_response_size, wasm_vm_enclave_id);
    if(ke_status != SUCCESS)
    {
        printf("Gateway Enclave: Failed to send/receive from WASM VM enclave. ke_status = %d\n", ke_status);
        return ke_status;
    }

    return SUCCESS;
}

/* Function Description:
 *   This is ECALL interface to close secure session*/
uint32_t test_close_session(sgx_enclave_id_t wasm_vm_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;

    ke_status = close_session(&g_src_session_info_map.find(wasm_vm_enclave_id)->second, wasm_vm_enclave_id);

    //Erase the session context
    memset(&g_src_session_info_map.find(wasm_vm_enclave_id)->second, 0, sizeof(dh_session_t));
    return ke_status;
}

/* Function Description:
 *   This is to verify peer enclave's identity.
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable: it's INITIALIZED'ed enclave; in non-debug build configuration, the enclave isn't loaded with enclave debug mode.
 **/
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity, sgx_enclave_id_t wasm_vm_enclave_id)
{
    if (!peer_enclave_identity) {
        printf("peer enclave identity is empty\n");
        return INVALID_PARAMETER_ERROR;
    }

    // check peer enclave's MRSIGNER
    if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_wasm_vm_mrsigner, sizeof(sgx_measurement_t))) {
        printf("peer enclave mr_signer mismatch\n");
        return ENCLAVE_TRUST_ERROR;
    }

    // check peer enclave's product ID and enclave attribute (should be INITIALIZED'ed)
    if (peer_enclave_identity->isv_prod_id != WASM_VM_PRODID || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED)) {
        printf("peer enclave PRODID wrong or INITED\n");
        return ENCLAVE_TRUST_ERROR;
    }

    // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
    if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
    	return ENCLAVE_TRUST_ERROR;
#endif

    return SUCCESS;
}

//Generates the response from the request message
/* Function Description:
 *   process request message and generate response
 * Parameter Description:
 *   [input] decrypted_data: this is pointer to decrypted message
 *   [input] decrypted_data_size: the size of decrypted_data
 *   [output] resp_buffer: this is pointer to response message, the buffer is allocated inside this function
 *   [output] resp_length: this points to response length
 * */
extern "C" uint32_t message_exchange_response_generator(uint8_t* decrypted_data,
                                              uint64_t decrypted_data_size,
                                              uint64_t max_output_length,
                                              uint8_t* resp_buffer,
                                              size_t* resp_length)
{
    uint32_t status;

    if(!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }

    // Send
    status = encrypt_to_enclave(/* wasm_vm_enclave_id[0] */&g_src_session_info_map.find(1)->second, decrypted_data,
                                                decrypted_data_size, max_output_length, resp_buffer, resp_length, 1);
    if(status != SUCCESS)
    {
        printf("Gateway Enclave: encrypt_to_enclave failed with %d\n", status);
        return status;
    }

    printf("Gateway Enclave: response length = %ld\n", *resp_length);

    return SUCCESS;
}
