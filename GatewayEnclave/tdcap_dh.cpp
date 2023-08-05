#include "error_codes.h"
#define __memset __unsan_memset
#include "tdcap_dh.h"
#include "sgx_dh_internal.h"
#include "sgx_trts.h"
#include "stdlib.h"
#include "string.h"
#include <sgx_secure_align.h>
#include <limits.h>

#include "sgx_utils.h"
#include "../GatewayEnclave/GatewayEnclave_t.h"
#include "ecp_interface.h"

#define NONCE_SIZE              16
#define MSG_BUF_LEN             (static_cast<uint32_t>(sizeof(sgx_ec256_public_t)*2))
#define MSG_HASH_SZ             32

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#ifndef INTERNAL_SGX_ERROR_CODE_CONVERTOR
#define INTERNAL_SGX_ERROR_CODE_CONVERTOR(x) if(x != SGX_ERROR_OUT_OF_MEMORY){x = SGX_ERROR_UNEXPECTED;}
#endif

extern int printf(const char* fmt, ...);

static sgx_status_t dh_dcap_generate_message2(const sgx_dh_dcap_msg1_t *msg1,
                                         const sgx_ec256_public_t *g_b,
                                         const sgx_key_128bit_t *dh_smk,
                                         sgx_dh_dcap_msg2_t *msg2);

template <decltype(dh_dcap_generate_message2) gen_msg2>
static sgx_status_t dh_dcap_initiator_proc_msg1(const sgx_dh_dcap_msg1_t* msg1, sgx_dh_dcap_msg2_t* msg2, sgx_dh_session_t* sgx_dh_session);

static sgx_status_t dh_dcap_verify_message3(const sgx_dh_dcap_msg3_t *msg3,
                                       const sgx_ec256_public_t *g_a,
                                       const sgx_ec256_public_t *g_b,
                                       const sgx_key_128bit_t *dh_smk);

template <decltype(dh_dcap_verify_message3) ver_msg3>
static sgx_status_t dh_dcap_initiator_proc_msg3(const sgx_dh_dcap_msg3_t* msg3,
    sgx_dh_session_t* sgx_dh_session, sgx_key_128bit_t* aek,
    sgx_dh_session_enclave_identity_t* responder_identity);



static sgx_status_t dh_dcap_generate_message1(sgx_dh_dcap_msg1_t *msg1, sgx_internal_dh_session_t *context);

static sgx_status_t dh_dcap_generate_message3(const sgx_dh_dcap_msg2_t *msg2,
                                         const sgx_ec256_public_t *g_a,
                                         const sgx_key_128bit_t *dh_smk,
                                         sgx_dh_dcap_msg3_t *msg3);


#define MAC_KEY_SIZE       16

#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

static sgx_status_t verify_cmac128(
    const sgx_ec_key_128bit_t mac_key,
    const uint8_t* data_buf,
    uint32_t buf_size,
    const uint8_t* mac_buf)
{
    uint8_t data_mac[SGX_CMAC_MAC_SIZE];
    sgx_status_t se_ret = SGX_SUCCESS;

    if(!data_buf || !mac_buf || !mac_key)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    se_ret = sgx_rijndael128_cmac_msg((const sgx_cmac_128bit_key_t*)mac_key,
                                      data_buf,
                                      buf_size,
                                      (sgx_cmac_128bit_tag_t *)data_mac);
    if(SGX_SUCCESS != se_ret)
    {
        return se_ret;
    }
    if(consttime_memequal(mac_buf, data_mac, SGX_CMAC_MAC_SIZE) == 0)
    {
        return SGX_ERROR_MAC_MISMATCH;
    }

    return se_ret;
}

// sgx_status_t sgx_dh_dcap_init_session()
// @role indicates whether the caller is a Initiator (starting the session negotiation) or a Responder (responding to the initial session negotiation request).
// @sgx_dh_session is the context of the session.
sgx_status_t sgx_dh_dcap_init_session(sgx_dh_session_role_t role, sgx_dh_session_t* sgx_dh_session)
{
    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*)sgx_dh_session;

    if(!session)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(SGX_DH_SESSION_INITIATOR != role && SGX_DH_SESSION_RESPONDER != role)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memset(session, 0, sizeof(sgx_internal_dh_session_t));

    if(SGX_DH_SESSION_INITIATOR == role)
    {
        session->initiator.state = SGX_DH_SESSION_INITIATOR_WAIT_M1;
    }
    else
    {
        session->responder.state = SGX_DH_SESSION_STATE_RESET;
    }

    session->role = role;

    return SGX_SUCCESS;
}

//sgx_dh_dcap_initiator_proc_msg1 processes M1 message, generates M2 message and makes update to the context of the session.
sgx_status_t sgx_dh_dcap_initiator_proc_msg1(const sgx_dh_dcap_msg1_t* msg1,
    sgx_dh_dcap_msg2_t* msg2, sgx_dh_session_t* sgx_dh_session)
{
    return dh_dcap_initiator_proc_msg1<dh_dcap_generate_message2>(msg1, msg2, sgx_dh_session);
}

template <decltype(dh_dcap_generate_message2) gen_msg2>
static sgx_status_t dh_dcap_initiator_proc_msg1(const sgx_dh_dcap_msg1_t* msg1, sgx_dh_dcap_msg2_t* msg2, sgx_dh_session_t* sgx_dh_session)
{
    sgx_status_t se_ret;

    sgx_ec256_public_t pub_key;
    sgx_ec256_private_t priv_key;
    sgx_ec256_dh_shared_t shared_key;
    sgx_key_128bit_t dh_smk;

    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*) sgx_dh_session;

    // validate session
    if(!session)
    {
        printf("Gateway Enclave: proc_msg1: no session\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if( !msg1 || !msg2 || SGX_DH_SESSION_INITIATOR != session->role)
    {
        // clear secret when encounter error
        printf("Gateway Enclave: proc_msg1: no msg or session initiator error\n");
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(SGX_DH_SESSION_INITIATOR_WAIT_M1 != session->initiator.state)
    {
        printf("Gateway Enclave: proc_msg1: session state error\n");
        // clear secret
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        return SGX_ERROR_INVALID_STATE;
    }

    //create ECC context
    sgx_ecc_state_handle_t ecc_state = NULL;
    se_ret = sgx_ecc256_open_context(&ecc_state);
    if(SGX_SUCCESS != se_ret)
    {
        printf("Gateway Enclave: proc_msg1: failed t open ecc context\n");
        goto error;
    }
    // generate private key and public key
    se_ret = sgx_ecc256_create_key_pair((sgx_ec256_private_t*)&priv_key,
                                       (sgx_ec256_public_t*)&pub_key,
                                        ecc_state);
    if(SGX_SUCCESS != se_ret)
    {
        printf("Gateway Enclave: proc_msg1: failed to create key pair\n");
        goto error;
    }

    //generate shared_key
    se_ret = sgx_ecc256_compute_shared_dhkey(
                                            (sgx_ec256_private_t *)const_cast<sgx_ec256_private_t*>(&priv_key),
                                            (sgx_ec256_public_t *)const_cast<sgx_ec256_public_t*>(&msg1->g_a),
                                            (sgx_ec256_dh_shared_t *)&shared_key,
                                             ecc_state);

    // clear private key for defense in depth
    memset(&priv_key, 0, sizeof(sgx_ec256_private_t));

    if(SGX_SUCCESS != se_ret)
    {
        
        printf("Gateway Enclave: proc_msg1: failed to compute shared dhkey\n");
        goto error;
    }

    se_ret = derive_key(&shared_key, "SMK", (uint32_t)(sizeof("SMK") -1), &dh_smk);
    if(SGX_SUCCESS != se_ret)
    {
        printf("Gateway Enclave: proc_msg1: failed to derive key\n");
        goto error;
    }

    se_ret = gen_msg2(msg1, &pub_key, &dh_smk, msg2);
    if(SGX_SUCCESS != se_ret)
    {
        printf("Gateway Enclave: proc_msg1: failed to generate msg2\n");
        goto error;
    }

    memcpy(&session->initiator.pub_key, &pub_key, sizeof(sgx_ec256_public_t));
    memcpy(&session->initiator.peer_pub_key, &msg1->g_a, sizeof(sgx_ec256_public_t));
    memcpy(&session->initiator.smk_aek, &dh_smk, sizeof(sgx_key_128bit_t));
    memcpy(&session->initiator.shared_key, &shared_key, sizeof(sgx_ec256_dh_shared_t));
    // clear shared key and SMK
    memset(&shared_key, 0, sizeof(sgx_ec256_dh_shared_t));
    memset(&dh_smk, 0, sizeof(sgx_key_128bit_t));

    if(SGX_SUCCESS != sgx_ecc256_close_context(ecc_state))
    {
        printf("Gateway Enclave: proc_msg1: failed to close context\n");
        // clear session
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        // set error state
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        return SGX_ERROR_UNEXPECTED;
    }

    session->initiator.state = SGX_DH_SESSION_INITIATOR_WAIT_M3;
    return SGX_SUCCESS;

error:
    sgx_ecc256_close_context(ecc_state);

    // clear shared key and SMK
    memset(&shared_key, 0, sizeof(sgx_ec256_dh_shared_t));
    memset(&dh_smk, 0, sizeof(sgx_key_128bit_t));

    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    session->initiator.state = SGX_DH_SESSION_STATE_ERROR;

    // return selected error to upper layer
    INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret)

    return se_ret;
}

static sgx_status_t dh_dcap_generate_message2(const sgx_dh_dcap_msg1_t *msg1,
                                         const sgx_ec256_public_t *g_b,
                                         const sgx_key_128bit_t *dh_smk,
                                         sgx_dh_dcap_msg2_t *msg2)
{
    sgx_status_t se_ret = SGX_SUCCESS;

    if(!msg1 || !g_b || !dh_smk || !msg2)
    {
        printf("Gateway Enclave: gen_msg2: no msg1 or no pub key or no smk or no msg2\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memset(msg2, 0, sizeof(sgx_dh_dcap_msg2_t));
    memcpy(&msg2->g_b, g_b, sizeof(sgx_ec256_public_t));

    if(SGX_SUCCESS != se_ret)
    {
        return se_ret;
    }

    return SGX_SUCCESS;
}

//sgx_dh_dcap_initiator_proc_msg3 processes M3 message, and returns the session key AEK.
sgx_status_t sgx_dh_dcap_initiator_proc_msg3(const sgx_dh_dcap_msg3_t* msg3,
    sgx_dh_session_t* sgx_dh_session, sgx_key_128bit_t* aek,
    sgx_dh_session_enclave_identity_t* responder_identity)
{
    return dh_dcap_initiator_proc_msg3<dh_dcap_verify_message3>(
        msg3, sgx_dh_session, aek, responder_identity);
}

template <decltype(dh_dcap_verify_message3) ver_msg3>
static sgx_status_t dh_dcap_initiator_proc_msg3(const sgx_dh_dcap_msg3_t* msg3,
    sgx_dh_session_t* sgx_dh_session, sgx_key_128bit_t* aek,
    sgx_dh_session_enclave_identity_t* responder_identity)
{
    sgx_status_t se_ret;
    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*)sgx_dh_session;

    // validate session
    if(!session)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(!msg3 ||
        msg3->msg3_body.quote_size > UINT_MAX  || // check msg3 length overflow
        SGX_DH_SESSION_INITIATOR != session->role) // role must be SGX_DH_SESSION_INITIATOR
    {
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(SGX_DH_SESSION_INITIATOR_WAIT_M3 != session->initiator.state) // protocol state must be SGX_DH_SESSION_INITIATOR_WAIT_M3
    {
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        return SGX_ERROR_INVALID_STATE;
    }

    se_ret = ver_msg3(msg3, &session->initiator.peer_pub_key,
        &session->initiator.pub_key, &session->initiator.smk_aek);
    if(SGX_SUCCESS != se_ret)
    {
        goto error;
    }

    // derive AEK
    se_ret = derive_key(&session->initiator.shared_key, "AEK", (uint32_t)(sizeof("AEK") -1), aek);
    if(SGX_SUCCESS != se_ret)
    {
        goto error;
    }

    // clear session
    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    session->initiator.state = SGX_DH_SESSION_ACTIVE;

    // copy the common fields between REPORT and the responder enclave identity
    memcpy(responder_identity, &(((sgx_quote3_t*)msg3->msg3_body.quote_buffer)->report_body), sizeof(sgx_dh_session_enclave_identity_t));

    return SGX_SUCCESS;

error:
    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
    INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret)
    return se_ret;
}

static sgx_status_t dh_dcap_verify_message3(const sgx_dh_dcap_msg3_t *msg3,
                                       const sgx_ec256_public_t *g_a,
                                       const sgx_ec256_public_t *g_b,
                                       const sgx_key_128bit_t *dh_smk)
{
    uint8_t* quote;
    quote = (uint8_t *)malloc(SGX_QUOTE3_BUFFER_SIZE);
    if(!quote)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint32_t quote_size;
    uint32_t maced_size;
    sgx_status_t se_ret;

    if(!msg3 || !g_a || !g_b || !dh_smk)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    maced_size = static_cast<uint32_t>(sizeof(sgx_dh_dcap_msg3_body_t));

    //Verify the MAC of message 3 obtained from the Session Responder
    se_ret = verify_cmac128((const uint8_t*)dh_smk, (const uint8_t*)&msg3->msg3_body, maced_size, msg3->cmac);
    if(SGX_SUCCESS != se_ret)
    {
        return se_ret;
    }

    memcpy(&quote_size, &msg3->msg3_body.quote_size, sizeof(uint32_t));
    memcpy(quote, &msg3->msg3_body.quote_buffer, quote_size);

    // Verify message 3 report
    uint32_t retstatus;
    se_ret = ecdsa_quote_verification_ocall(&retstatus, quote, quote_size);
    if (se_ret == SGX_SUCCESS)
    {
        if (retstatus == -1)
            return se_ret;
    }
    else
    {
        return se_ret;
    }

    return SGX_SUCCESS;
}

static sgx_status_t dh_dcap_generate_message1(sgx_dh_dcap_msg1_t *msg1, sgx_internal_dh_session_t *context)
{
    sgx_status_t se_ret;
    sgx_ecc_state_handle_t ecc_state = NULL;

    if(!msg1 || !context)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    //Initialize ECC context to prepare for creating key pair
    se_ret = sgx_ecc256_open_context(&ecc_state);
    if(se_ret != SGX_SUCCESS)
    {
        return se_ret;
    }
    //Generate the public key private key pair for Session Responder
    se_ret = sgx_ecc256_create_key_pair((sgx_ec256_private_t*)&context->responder.prv_key,
                                       (sgx_ec256_public_t*)&context->responder.pub_key,
                                       ecc_state);
    if(se_ret != SGX_SUCCESS)
    {
         sgx_ecc256_close_context(ecc_state);
         return se_ret;
    }

    //Copying public key to g^a
    memcpy(&msg1->g_a,
           &context->responder.pub_key,
           sizeof(sgx_ec256_public_t));

    se_ret = sgx_ecc256_close_context(ecc_state);
    if(SGX_SUCCESS != se_ret)
    {
        return se_ret;
    }

    return SGX_SUCCESS;
}

// Function sgx_dh_dcap_responder_gen_msg1 generates M1 message and makes update to the context of the session.
sgx_status_t sgx_dh_dcap_responder_gen_msg1(sgx_dh_dcap_msg1_t* msg1, sgx_dh_session_t* sgx_dh_session)
{
    sgx_status_t se_ret;
    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*)sgx_dh_session;

    // validate session
    if(!session)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(!msg1 ||
       SGX_DH_SESSION_RESPONDER != session->role)
    {
        se_ret = SGX_ERROR_INVALID_PARAMETER;
        goto error;
    }

    if(SGX_DH_SESSION_STATE_RESET != session->responder.state)
    {
        se_ret = SGX_ERROR_INVALID_STATE;
        goto error;
    }

    se_ret = dh_dcap_generate_message1(msg1, session);
    if(SGX_SUCCESS != se_ret)
    {
        // return selected error to upper layer
        INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret)
        goto error;
    }

    session->responder.state = SGX_DH_SESSION_RESPONDER_WAIT_M2;

    return SGX_SUCCESS;
error:
    // clear session
    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    session->responder.state = SGX_DH_SESSION_STATE_ERROR;
    return se_ret;
}

static sgx_status_t dh_dcap_generate_message3(const sgx_dh_dcap_msg2_t *msg2,
                                         const sgx_ec256_public_t *g_a,
                                         const sgx_key_128bit_t *dh_smk,
                                         sgx_dh_dcap_msg3_t *msg3)
{
    sgx_report_t app_report;
    sgx_report_data_t report_data;
    sgx_status_t se_ret = SGX_SUCCESS;
    uint32_t maced_size;

    uint8_t msg_buf[MSG_BUF_LEN] = {0};
    uint8_t msg_hash[MSG_HASH_SZ] = {0};

    if(!msg2 || !g_a || !dh_smk || !msg3)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    maced_size = static_cast<uint32_t>(sizeof(sgx_dh_dcap_msg3_body_t));

    memset(msg3, 0, sizeof(sgx_dh_dcap_msg3_t));

    memcpy(msg_buf, &msg2->g_b, sizeof(sgx_ec256_public_t));
    memcpy(msg_buf + sizeof(sgx_ec256_public_t), g_a, sizeof(sgx_ec256_public_t));

    se_ret = sgx_sha256_msg(msg_buf,
                            MSG_BUF_LEN,
                            (sgx_sha256_hash_t *)msg_hash);
    if(se_ret != SGX_SUCCESS)
    {
        return se_ret;
    }

    // Get REPORT with SHA256(g_b||g_a) as user data
    memset(&report_data, 0, sizeof(sgx_report_data_t));
    memcpy(&report_data, &msg_hash, sizeof(msg_hash));

    sgx_target_info_t qe_target_info;
    uint32_t retstatus;
    se_ret = ecdsa_get_qe_target_info_ocall(&retstatus, &qe_target_info);
    if (SGX_SUCCESS == se_ret) {
        if (retstatus != 0)
            return se_ret;
    }
    else
    {
        return se_ret;
    }

    // Get quoting enclave target info
    se_ret = sgx_create_report(&qe_target_info, &report_data, &app_report);
    if (SGX_SUCCESS != se_ret) {
        return se_ret;
    }

    // Generate quote
    uint8_t* quote_buffer;
    quote_buffer = (uint8_t *)malloc(SGX_QUOTE3_BUFFER_SIZE);
    if(!quote_buffer)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint32_t quote_size;
    se_ret = ecdsa_quote_generation_ocall(&retstatus, &quote_size, &app_report, quote_buffer);
    if (se_ret == SGX_SUCCESS)
    {
        if (retstatus == -1)
            return se_ret;
    }
    else
    {
        return se_ret;
    }
    memcpy(&msg3->msg3_body.quote_size,
           &quote_size,
           sizeof(uint32_t));
    memcpy(msg3->msg3_body.quote_buffer,
           quote_buffer,
           SGX_QUOTE3_BUFFER_SIZE);

    // // Verify message 3 report
    // se_ret = ecdsa_quote_verification_ocall(&retstatus, msg3->msg3_body.quote_buffer, quote_size);

    //Calculate the MAC for Message 3
    se_ret = sgx_rijndael128_cmac_msg(dh_smk,
                                      (uint8_t *)&msg3->msg3_body,
                                      maced_size,
                                      (sgx_cmac_128bit_tag_t *)msg3->cmac);
    if(se_ret != SGX_SUCCESS)
    {
        return se_ret;
    }

    return SGX_SUCCESS;

}

//sgx_dh_dcap_responder_proc_msg2 processes M2 message, generates M3 message, and returns the session key AEK.
sgx_status_t sgx_dh_dcap_responder_proc_msg2(const sgx_dh_dcap_msg2_t* msg2,
                                        sgx_dh_dcap_msg3_t* msg3,
                                        sgx_dh_session_t* sgx_dh_session,
                                        sgx_key_128bit_t* aek)
{
    sgx_status_t se_ret;

    //
    // securely align shared key
    //
    //sgx_ec256_dh_shared_t shared_key;
    sgx::custom_alignment<sgx_ec256_dh_shared_t, 0, sizeof(sgx_ec256_dh_shared_t)> oshared_key;
    sgx_ec256_dh_shared_t& shared_key = oshared_key.v;
    //
    // securely align smk
    //
    //sgx_key_128bit_t dh_smk;
    sgx::custom_alignment_aligned<sgx_key_128bit_t, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t)> odh_smk;
    sgx_key_128bit_t& dh_smk = odh_smk.v;

    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*)sgx_dh_session;

    // validate session
    if(!session )
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(!msg3 ||
        sizeof(msg3->msg3_body) + sizeof(msg3->cmac) > UINT_MAX || // check msg3 length overflow
        !msg2 ||
        !aek ||
        SGX_DH_SESSION_RESPONDER != session->role)
    {
        // clear secret when encounter error
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->responder.state = SGX_DH_SESSION_STATE_ERROR;
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if(SGX_DH_SESSION_RESPONDER_WAIT_M2 != session->responder.state) // protocol state must be SGX_DH_SESSION_RESPONDER_WAIT_M2
    {
        // clear secret
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->responder.state = SGX_DH_SESSION_STATE_ERROR;
        return SGX_ERROR_INVALID_STATE;
    }

    //create ECC context, and the ECC parameter is
    //NIST standard P-256 elliptic curve.
    sgx_ecc_state_handle_t ecc_state = NULL;
    se_ret = sgx_ecc256_open_context(&ecc_state);
    if(SGX_SUCCESS != se_ret)
    {
        goto error;
    }

    //generate shared key, which should be identical with enclave side,
    //from PSE private key and enclave public key
    se_ret = sgx_ecc256_compute_shared_dhkey((sgx_ec256_private_t *)&session->responder.prv_key,
                                            (sgx_ec256_public_t *)const_cast<sgx_ec256_public_t*>(&msg2->g_b),
                                            (sgx_ec256_dh_shared_t *)&shared_key,
                                             ecc_state);

    // For defense-in-depth purpose, responder clears its private key from its enclave memory, as it's not needed anymore.
    memset(&session->responder.prv_key, 0, sizeof(sgx_ec256_private_t));

    if(se_ret != SGX_SUCCESS)
    {
        goto error;
    }

    //derive keys from session shared key
    se_ret = derive_key(&shared_key, "SMK", (uint32_t)(sizeof("SMK") -1), &dh_smk);
    if(se_ret != SGX_SUCCESS)
    {
        goto error;
    }

    // Generate message 3 to send back to initiator
    se_ret = dh_dcap_generate_message3(msg2, &session->responder.pub_key, &dh_smk, msg3);
    if(SGX_SUCCESS != se_ret)
    {
        goto error;
    }

    // derive session key
    se_ret = derive_key(&shared_key, "AEK", (uint32_t)(sizeof("AEK") -1), aek);
    if(se_ret != SGX_SUCCESS)
    {
        goto error;
    }

    // clear secret
    memset(&shared_key, 0, sizeof(sgx_ec256_dh_shared_t));
    memset(&dh_smk, 0, sizeof(sgx_key_128bit_t));
    // clear session
    memset(session, 0, sizeof(sgx_internal_dh_session_t));

    se_ret = sgx_ecc256_close_context(ecc_state);
    if(SGX_SUCCESS != se_ret)
    {
        // set error state
        session->responder.state = SGX_DH_SESSION_STATE_ERROR;
        return SGX_ERROR_UNEXPECTED;
    }

    // set state
    session->responder.state = SGX_DH_SESSION_ACTIVE;

    return SGX_SUCCESS;

error:
    sgx_ecc256_close_context(ecc_state);
    // clear secret
    memset(&shared_key, 0, sizeof(sgx_ec256_dh_shared_t));
    memset(&dh_smk, 0, sizeof(sgx_key_128bit_t));
    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    // set error state
    session->responder.state = SGX_DH_SESSION_STATE_ERROR;
    // return selected error to upper layer
    if (se_ret != SGX_ERROR_OUT_OF_MEMORY &&
        se_ret != SGX_ERROR_KDF_MISMATCH)
    {
        se_ret = SGX_ERROR_UNEXPECTED;
    }
    return se_ret;
}
