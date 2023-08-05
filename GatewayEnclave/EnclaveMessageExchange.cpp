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

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "EnclaveMessageExchange.h"
#include "sgx_eid.h"
#include "error_codes.h"
#include "sgx_ecp_types.h"
#include "sgx_thread.h"
#include <map>
#include "dh_session_protocol.h"

#include "sgx_tcrypto.h"
#include "../GatewayEnclave/GatewayEnclave_t.h"

#include <stdio.h>
#include <string.h>

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

#include "dcap_dh_def.h"
#include "tdcap_dh.h"
#ifdef __cplusplus
extern "C"
{
#endif
    uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t *peer_enclave_identity, sgx_enclave_id_t wasm_vm_enclave_id);
    uint32_t message_exchange_response_generator(uint8_t *decrypted_data, uint64_t decrypted_data_size, uint64_t max_resp_length, uint8_t *resp_buffer, size_t *resp_length);

#ifdef __cplusplus
}
#endif


#define MAX_SESSION_COUNT 16

// number of open sessions
uint32_t g_session_count = 0;

ATTESTATION_STATUS generate_session_id(uint32_t *session_id);
extern "C" ATTESTATION_STATUS end_session(uint32_t session_id);

// Array of open session ids
session_id_tracker_t *g_session_id_tracker[MAX_SESSION_COUNT];

// Map between the source isv session id and the session information associated with that particular session
std::map<uint32_t, dh_session_t> g_dest_session_info_map;

// Create a session with the destination enclave
ATTESTATION_STATUS create_session(dh_session_t *session_info, sgx_enclave_id_t wasm_vm_enclave_id)
{
    sgx_dh_dcap_msg1_t dh_msg1; // Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;    // Session Key
    sgx_dh_dcap_msg2_t dh_msg2; // Diffie-Hellman Message 2
    sgx_dh_dcap_msg3_t dh_msg3; // Diffie-Hellman Message 3
    uint32_t session_id;
    uint32_t retstatus;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    if (!session_info)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_dcap_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_dcap_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_dcap_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));

    // Intialize the session as a session initiator
    status = sgx_dh_dcap_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
        return status;
    }

	printf("Gateway Enclave: Requesting session from wasm vm...\n");
    // Ocall to request for a session with the destination enclave and obtain session id and Message 1 if successful
    status = session_request_ocall(&retstatus, &dh_msg1, &session_id, wasm_vm_enclave_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS) {
            printf("Gateway Enclave: Session request failed with %d\n", (uint32_t)retstatus);
            return ((ATTESTATION_STATUS)retstatus);
        }
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    // Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_dcap_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
        printf("Gateway Enclave: MSG1 process failed with %d\n", (uint32_t)status);
        return status;
    }
	printf("Gateway Enclave: Requesting session from wasm vm success\n");

    // Send Message 2 to Destination Enclave and get Message 3 in return
    status = exchange_report_ocall(&retstatus, &dh_msg2, &dh_msg3, session_id, wasm_vm_enclave_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS) {
	    printf("Gateway Enclave: Report exchange failed with %d\n", (uint32_t)retstatus);
            return ((ATTESTATION_STATUS)retstatus);
        }
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
	printf("Gateway Enclave: Processed message 2 from WASM VM\n");

    // Process Message 3 obtained from the destination enclave
    status = sgx_dh_dcap_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if (SGX_SUCCESS != status)
    {
        printf("msg3 failed\n");
        return status;
    }

    // Verify the identity of the destination enclave
    if (verify_peer_enclave_trust(&responder_identity, wasm_vm_enclave_id) != SUCCESS)
    {
        printf("peer trust failed\n");
        return INVALID_SESSION;
    }

    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    
        printf("AEK [0] = 0x%016llX\n", ((uint64_t*)session_info->active.AEK)[0]);
        printf("AEK [1] = 0x%016llX\n", ((uint64_t*)session_info->active.AEK)[1]);
    session_info->session_id = session_id;
    session_info->active.counter = 0;
    session_info->status = ACTIVE;
    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
    return status;
}

// Request for the response size, send the request message to the destination enclave and receive the response message back
ATTESTATION_STATUS encrypt_to_enclave(dh_session_t *session_info,
                                                 uint8_t *inp_buff,
                                                 size_t inp_buff_len,
                                                 size_t max_out_buff_size,
                                                 uint8_t *out_buff,
                                                 size_t *out_buff_len,
                                                 sgx_enclave_id_t wasm_vm_enclave_id)
{
    const uint8_t *plaintext;
    uint32_t plaintext_length;
    sgx_status_t status;
    secure_message_t *resp_message;
    plaintext = (const uint8_t *)(" ");
    plaintext_length = 0;

    resp_message = (secure_message_t *)out_buff;

    if (!session_info || !inp_buff)
    {
        return INVALID_PARAMETER_ERROR;
    }

    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;

    // Set the payload size to data to encrypt length
    resp_message->message_aes_gcm_data.payload_size = data2encrypt_length;
    if (data2encrypt_length + sizeof(secure_message_t) > max_out_buff_size) {
        return OUT_BUFFER_LENGTH_ERROR;
    }

    // Use the session nonce as the payload IV
    memcpy(resp_message->message_aes_gcm_data.reserved, &session_info->active.counter, sizeof(session_info->active.counter));

    // Set the session ID of the message to the current session id
    resp_message->session_id = resp_message->session_id;
    printf("Gateway Enclave: session_id = %d\n", session_info->session_id);

    // Prepare the request message with the encrypted payload
    status = sgx_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t *)inp_buff, data2encrypt_length,
                                        reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.payload)),
                                        reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.reserved)),
                                        sizeof(resp_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                                        &(resp_message->message_aes_gcm_data.payload_tag));

    if (SGX_SUCCESS != status)
    {
        printf("Gateway Enclave: encrypt_to_enclave: Failed to encrypt\n");
        return status;
    }
    
    printf("payload_tag [0] = 0x%016llX\n", ((uint64_t*)resp_message->message_aes_gcm_data.payload_tag)[0]);
        printf("payload_tag [1] = 0x%016llX\n", ((uint64_t*)resp_message->message_aes_gcm_data.payload_tag)[1]);
        printf("AEK [0] = 0x%016llX\n", ((uint64_t*)session_info->active.AEK)[0]);
        printf("AEK [1] = 0x%016llX\n", ((uint64_t*)session_info->active.AEK)[1]);
        printf("iv = 0x%016llX\n", ((uint64_t*)resp_message->message_aes_gcm_data.reserved)[0]);

    *out_buff_len = data2encrypt_length;
    
    printf("payload_size = %lld\n", 
    resp_message->message_aes_gcm_data.payload_size);

    return SUCCESS;
}

// Close a current session
ATTESTATION_STATUS close_session(dh_session_t *session_info, sgx_enclave_id_t wasm_vm_enclave_id)
{
    sgx_status_t status;
    uint32_t retstatus;

    if (!session_info)
    {
        return INVALID_PARAMETER_ERROR;
    }

    // Ocall to ask the destination enclave to end the session
    status = end_session_ocall(&retstatus, session_info->session_id, wasm_vm_enclave_id);
    if (status == SGX_SUCCESS)
    {
        if ((ATTESTATION_STATUS)retstatus != SUCCESS)
            return ((ATTESTATION_STATUS)retstatus);
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    return SUCCESS;
}

// Returns a new sessionID for the source destination session
ATTESTATION_STATUS generate_session_id(uint32_t *session_id)
{
    ATTESTATION_STATUS status = SUCCESS;

    if (!session_id)
    {
        return INVALID_PARAMETER_ERROR;
    }
    // if the session structure is uninitialized, set that as the next session ID
    for (int i = 0; i < MAX_SESSION_COUNT; i++)
    {
        if (g_session_id_tracker[i] == NULL)
        {
            *session_id = i;
            return status;
        }
    }

    status = NO_AVAILABLE_SESSION_ERROR;

    return status;
}

/*---------------------------------------------------------------------------------------------*/

// Handle the request from ISV for a session
extern "C" ATTESTATION_STATUS session_request(sgx_dh_dcap_msg1_t *dh_msg1,
                                              uint32_t *session_id)
{
    dh_session_t session_info;
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;

    if (!session_id || !dh_msg1)
    {
        return INVALID_PARAMETER_ERROR;
    }
    // Intialize the session as a session responder
    status = sgx_dh_dcap_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
        return status;
    }

    // get a new SessionID
    if ((status = (sgx_status_t)generate_session_id(session_id)) != SUCCESS)
        return status; // no more sessions available

    // Allocate memory for the session id tracker
    g_session_id_tracker[*session_id] = (session_id_tracker_t *)malloc(sizeof(session_id_tracker_t));
    if (!g_session_id_tracker[*session_id])
    {
        return MALLOC_ERROR;
    }

    memset(g_session_id_tracker[*session_id], 0, sizeof(session_id_tracker_t));
    g_session_id_tracker[*session_id]->session_id = *session_id;
    session_info.status = IN_PROGRESS;

    // Generate Message1 that will be returned to ISV 
    status = sgx_dh_dcap_responder_gen_msg1((sgx_dh_dcap_msg1_t *)dh_msg1, &sgx_dh_session);
    if (SGX_SUCCESS != status)
    {
        SAFE_FREE(g_session_id_tracker[*session_id]);
        return status;
    }
    memcpy(&session_info.in_progress.dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));
    // Store the session information under the corresponding ISV session id key
    g_dest_session_info_map.insert(std::pair<uint32_t, dh_session_t>(*session_id, session_info));

    return status;
}

// Verify Message 2, generate Message3 and exchange Message 3 with ISV
extern "C" ATTESTATION_STATUS exchange_report(sgx_dh_dcap_msg2_t *dh_msg2,
                                              sgx_dh_dcap_msg3_t *dh_msg3,
                                              uint32_t session_id)
{

    sgx_key_128bit_t dh_aek; // Session key
    dh_session_t *session_info;
    ATTESTATION_STATUS status = SUCCESS;
    sgx_dh_session_t sgx_dh_session;

    if (!dh_msg2 || !dh_msg3)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
    do
    {
        // Retrieve the session information for the corresponding ISV id
        std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
        if (it != g_dest_session_info_map.end())
        {
            session_info = &it->second;
        }
        else
        {
            status = INVALID_SESSION;
            break;
        }

        if (session_info->status != IN_PROGRESS)
        {
            status = INVALID_SESSION;
            break;
        }

        memcpy(&sgx_dh_session, &session_info->in_progress.dh_session, sizeof(sgx_dh_session_t));

        // Process message 2 from ISV and obtain message 3
        sgx_status_t se_ret = sgx_dh_dcap_responder_proc_msg2(dh_msg2,
                                                              dh_msg3,
                                                              &sgx_dh_session,
                                                              &dh_aek);
        if (SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }

        // save the session ID, status and initialize the session nonce
        session_info->session_id = session_id;
        session_info->status = ACTIVE;
        session_info->active.counter = 0;
        memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
        memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
        g_session_count++;
    } while (0);

    if (status != SUCCESS)
    {
        end_session(session_id);
    }

    return status;
}

// Process the request from the ISV and send the response message back to the ISV
extern "C" ATTESTATION_STATUS generate_response(secure_message_t *req_message,
                                                size_t req_message_size,
                                                size_t max_payload_size,
                                                secure_message_t *resp_message,
                                                size_t *resp_message_size,
                                                uint32_t session_id)
{
    const uint8_t *plaintext;
    uint32_t plaintext_length;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    size_t resp_data_length;
    size_t resp_message_calc_size;
    uint8_t *resp_data;
    uint8_t l_tag[TAG_SIZE];
    size_t header_size, expected_payload_size;
    dh_session_t *session_info;
    uint32_t ret;
    sgx_status_t status;

    plaintext = (const uint8_t *)(" ");
    plaintext_length = 0;

    printf("Entering...\n");
    if (!req_message || !resp_message)
    {
        printf("req or resp is null\n");
        return INVALID_PARAMETER_ERROR;
    }

    // Get the session information from the map corresponding to the ISV id
    std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if (it != g_dest_session_info_map.end())
    {
        session_info = &it->second;
    }
    else
    {
        printf("session invalid\n");
        return INVALID_SESSION;
    }

    if (session_info->status != ACTIVE)
    {
        printf("session inactive\n");
        return INVALID_SESSION;
    }

    // Set the decrypted data length to the payload size obtained from the message
    decrypted_data_length = req_message->message_aes_gcm_data.payload_size;
    
    header_size = sizeof(secure_message_t);
    expected_payload_size = req_message_size - header_size;
    printf("expected vs decrypted. %d vs %d\n", expected_payload_size, decrypted_data_length);

    // Verify the size of the payload
    if (expected_payload_size != decrypted_data_length) {
        printf("payload size unmatched. %d vs %d\n", expected_payload_size, decrypted_data_length);
        return INVALID_PARAMETER_ERROR;
    }

    memset(&l_tag, 0, 16);
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t *)malloc(decrypted_data_length);
    if (!decrypted_data)
    {
        printf("Failed to malloc\n");
        return MALLOC_ERROR;
    }

    memset(decrypted_data, 0, decrypted_data_length);

    // Decrypt the request message payload from ISV
    status = sgx_rijndael128GCM_decrypt(&session_info->active.AEK, req_message->message_aes_gcm_data.payload,
                                        decrypted_data_length, decrypted_data,
                                        reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                                        sizeof(req_message->message_aes_gcm_data.reserved), &(req_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length,
                                        &req_message->message_aes_gcm_data.payload_tag);

    if (SGX_SUCCESS != status)
    {
        printf("failed to decrypt %d\n", status);
        SAFE_FREE(decrypted_data);
        return status;
    }

    // Call the generic secret response generator for message exchange
    ret = message_exchange_response_generator(decrypted_data, decrypted_data_length, max_payload_size, (uint8_t *)resp_message, &resp_data_length);

    if (ret != 0)
    {
        printf("failed to encrypt %d\n", ret);
        SAFE_FREE(decrypted_data);
        return INVALID_SESSION;
    }

    if (resp_data_length > max_payload_size)
    {
        printf("resp data too large\n");
        SAFE_FREE(decrypted_data);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    resp_message_calc_size = sizeof(secure_message_t) + resp_data_length;

    if (resp_message_calc_size > *resp_message_size)
    {
        printf("resp msg size smaller than real\n");
        SAFE_FREE(decrypted_data);
        return OUT_BUFFER_LENGTH_ERROR;
    }

    *resp_message_size = resp_message_calc_size;

    SAFE_FREE(decrypted_data);
    printf("Success\n");

    return SUCCESS;
}

// Respond to the request from the ISV to close the session
extern "C" ATTESTATION_STATUS end_session(uint32_t session_id)
{
    ATTESTATION_STATUS status = SUCCESS;
    int i;
    dh_session_t session_info;
    // uint32_t session_id;

    // Get the session information from the map corresponding to the ISV id
    std::map<uint32_t, dh_session_t>::iterator it = g_dest_session_info_map.find(session_id);
    if (it != g_dest_session_info_map.end())
    {
        session_info = it->second;
    }
    else
    {
        return INVALID_SESSION;
    }

    // session_id = session_info.session_id;
    // Erase the session information for the current session
    g_dest_session_info_map.erase(session_id);

    // Update the session id tracker
    if (g_session_count > 0)
    {
        // check if session exists
        for (i = 1; i <= MAX_SESSION_COUNT; i++)
        {
            if (g_session_id_tracker[i - 1] != NULL && g_session_id_tracker[i - 1]->session_id == session_id)
            {
                memset(g_session_id_tracker[i - 1], 0, sizeof(session_id_tracker_t));
                SAFE_FREE(g_session_id_tracker[i - 1]);
                g_session_count--;
                break;
            }
        }
    }

    return status;
}
