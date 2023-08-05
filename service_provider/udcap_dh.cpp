#include "error_codes.h"

#include "sgx_dh_internal.h"
#include "udcap_dh.h"

#include <stdio.h>
#include <string.h>

#include <limits.h>
#include "sgx_dcap_ql_wrapper.h"


#include "sample_libcrypto.h"
#include "ecp.h"
#include "service_provider.h"

#define NONCE_SIZE              16
#define MSG_BUF_LEN             (static_cast<uint32_t>(sizeof(sample_ec256_public_t)*2))
#define MSG_HASH_SZ             32

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#ifndef INTERNAL_SGX_ERROR_CODE_CONVERTOR
#define INTERNAL_SGX_ERROR_CODE_CONVERTOR(x) if(x != SAMPLE_ERROR_OUT_OF_MEMORY){x = SAMPLE_ERROR_UNEXPECTED;}
#endif

typedef uint32_t ATTESTATION_STATUS;

static sample_status_t dh_dcap_generate_message2(const sgx_dh_dcap_msg1_t *msg1,
                                         const sample_ec256_public_t *g_b,
                                         const sample_key_128bit_t *dh_smk,
                                         sgx_dh_dcap_msg2_t *msg2);

template <decltype(dh_dcap_generate_message2) gen_msg2>
static sample_status_t dh_dcap_initiator_proc_msg1(const sgx_dh_dcap_msg1_t* msg1, sgx_dh_dcap_msg2_t* msg2, sgx_dh_session_t* sgx_dh_session);

static sample_status_t dh_dcap_verify_message3(const sgx_dh_dcap_msg3_t *msg3,
                                       const sample_ec256_public_t *g_a,
                                       const sample_ec256_public_t *g_b,
                                       const sample_key_128bit_t *dh_smk);

template <decltype(dh_dcap_verify_message3) ver_msg3>
static sample_status_t dh_dcap_initiator_proc_msg3(const sgx_dh_dcap_msg3_t* msg3,
    sgx_dh_session_t* sgx_dh_session, sample_key_128bit_t* aek,
    sgx_dh_session_enclave_identity_t* responder_identity);



static sample_status_t dh_dcap_generate_message1(sgx_dh_dcap_msg1_t *msg1, sgx_internal_dh_session_t *context);




#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

// sample_status_t sgx_dh_init_session()
// @role indicates whether the caller is a Initiator (starting the session negotiation) or a Responder (responding to the initial session negotiation request).
// @sgx_dh_session is the context of the session.
sample_status_t sgx_dh_dcap_init_session(sgx_dh_session_role_t role, sgx_dh_session_t* sgx_dh_session)
{
    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*)sgx_dh_session;

    if(!session)
    {
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    if(SGX_DH_SESSION_INITIATOR != role && SGX_DH_SESSION_RESPONDER != role)
    {
        return SAMPLE_ERROR_INVALID_PARAMETER;
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

    return SAMPLE_SUCCESS;
}

//sgx_dh_dcap_initiator_proc_msg1 processes M1 message, generates M2 message and makes update to the context of the session.
sample_status_t sgx_dh_dcap_initiator_proc_msg1(const sgx_dh_dcap_msg1_t* msg1,
    sgx_dh_dcap_msg2_t* msg2, sgx_dh_session_t* sgx_dh_session)
{
    return dh_dcap_initiator_proc_msg1<dh_dcap_generate_message2>(msg1, msg2, sgx_dh_session);
}

template <decltype(dh_dcap_generate_message2) gen_msg2>
static sample_status_t dh_dcap_initiator_proc_msg1(const sgx_dh_dcap_msg1_t* msg1, sgx_dh_dcap_msg2_t* msg2, sgx_dh_session_t* sgx_dh_session)
{
    sample_status_t se_ret;

    sample_ec256_public_t pub_key;
    sample_ec256_private_t priv_key;
    sample_ec256_dh_shared_t shared_key;
    sample_key_128bit_t dh_smk;

    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*) sgx_dh_session;

    // validate session
    if(!session)
    {
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    if( !msg1 || !msg2 || SGX_DH_SESSION_INITIATOR != session->role)
    {
        // clear secret when encounter error
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    if(SGX_DH_SESSION_INITIATOR_WAIT_M1 != session->initiator.state)
    {
        // clear secret
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        printf("The state of initiaor session is not SGX_DH_SESSION_INITIATOR_WAIT_M1");
        return SAMPLE_ERROR_UNEXPECTED;
    }

    //create ECC context
    sample_ecc_state_handle_t ecc_state = NULL;
    se_ret = sample_ecc256_open_context(&ecc_state);
    if(SAMPLE_SUCCESS != se_ret)
    {
        goto error;
    }
    // generate private key and public key
    se_ret = sample_ecc256_create_key_pair((sample_ec256_private_t*)&priv_key,
                                       (sample_ec256_public_t*)&pub_key,
                                        ecc_state);
    if(SAMPLE_SUCCESS != se_ret)
    {
        goto error;
    }

    //generate shared_key
    se_ret = sample_ecc256_compute_shared_dhkey(
                                            (sample_ec256_private_t *)const_cast<sample_ec256_private_t*>(&priv_key),
                                            (sample_ec256_public_t *)const_cast<sample_ec256_public_t*>((sample_ec256_public_t*)&msg1->g_a),
                                            (sample_ec256_dh_shared_t *)&shared_key,
                                             ecc_state);

    // clear private key for defense in depth
    memset(&priv_key, 0, sizeof(sample_ec256_private_t));

    if(SAMPLE_SUCCESS != se_ret)
    {
        goto error;
    }

    if(!derive_key((const sample_ec_dh_shared_t *)(&shared_key), SAMPLE_DERIVE_KEY_SMK, &dh_smk))
    {
        printf("derive smk error");
        se_ret = SAMPLE_ERROR_UNEXPECTED;
        goto error;
    }

    se_ret = gen_msg2(msg1, &pub_key, &dh_smk, msg2);
    if(SAMPLE_SUCCESS != se_ret)
    {
        goto error;
    }

    memcpy(&session->initiator.pub_key, &pub_key, sizeof(sample_ec256_public_t));
    memcpy(&session->initiator.peer_pub_key, &msg1->g_a, sizeof(sample_ec256_public_t));
    memcpy(&session->initiator.smk_aek, &dh_smk, sizeof(sample_key_128bit_t));
    memcpy(&session->initiator.shared_key, &shared_key, sizeof(sample_ec256_dh_shared_t));
    // clear shared key and SMK
    memset(&shared_key, 0, sizeof(sample_ec256_dh_shared_t));
    memset(&dh_smk, 0, sizeof(sample_key_128bit_t));

    if(SAMPLE_SUCCESS != sample_ecc256_close_context(ecc_state))
    {
        // clear session
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        // set error state
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        return SAMPLE_ERROR_UNEXPECTED;
    }

    session->initiator.state = SGX_DH_SESSION_INITIATOR_WAIT_M3;
    return SAMPLE_SUCCESS;

error:
    sample_ecc256_close_context(ecc_state);

    // clear shared key and SMK
    memset(&shared_key, 0, sizeof(sample_ec256_dh_shared_t));
    memset(&dh_smk, 0, sizeof(sample_key_128bit_t));

    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    session->initiator.state = SGX_DH_SESSION_STATE_ERROR;

    // return selected error to upper layer
    INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret)

    return se_ret;
}

static sample_status_t dh_dcap_generate_message2(const sgx_dh_dcap_msg1_t *msg1,
                                         const sample_ec256_public_t *g_b,
                                         const sample_key_128bit_t *dh_smk,
                                         sgx_dh_dcap_msg2_t *msg2)
{

    if(!msg1 || !g_b || !dh_smk || !msg2)
    {
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    memset(msg2, 0, sizeof(sgx_dh_dcap_msg2_t));
    memcpy(&msg2->g_b, g_b, sizeof(sample_ec256_public_t));


    return SAMPLE_SUCCESS;
}

//sgx_dh_dcap_initiator_proc_msg3 processes M3 message, and returns the session key AEK.
sample_status_t sgx_dh_dcap_initiator_proc_msg3(const sgx_dh_dcap_msg3_t* msg3,
    sgx_dh_session_t* sgx_dh_session, sample_key_128bit_t* aek,
    sgx_dh_session_enclave_identity_t* responder_identity)
{
    return dh_dcap_initiator_proc_msg3<dh_dcap_verify_message3>(
        msg3, sgx_dh_session, aek, responder_identity);
}

template <decltype(dh_dcap_verify_message3) ver_msg3>
static sample_status_t dh_dcap_initiator_proc_msg3(const sgx_dh_dcap_msg3_t* msg3,
    sgx_dh_session_t* sgx_dh_session, sample_key_128bit_t* aek,
    sgx_dh_session_enclave_identity_t* responder_identity)
{
    sample_status_t se_ret;
    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*)sgx_dh_session;

    // validate session
    if(!session)
    {
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    if(!msg3 ||
        msg3->msg3_body.quote_size > UINT_MAX  || // check msg3 length overflow
        SGX_DH_SESSION_INITIATOR != session->role) // role must be SGX_DH_SESSION_INITIATOR
    {
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    if(SGX_DH_SESSION_INITIATOR_WAIT_M3 != session->initiator.state) // protocol state must be SGX_DH_SESSION_INITIATOR_WAIT_M3
    {
        memset(session, 0, sizeof(sgx_internal_dh_session_t));
        session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
        printf("The state of initiator session is not SGX_DH_SESSION_INITIATOR_WAIT_M3");
        return SAMPLE_ERROR_UNEXPECTED;
    }

    se_ret = ver_msg3(msg3, &session->initiator.peer_pub_key,
        &session->initiator.pub_key, &session->initiator.smk_aek);
    if(SAMPLE_SUCCESS != se_ret)
    {
        goto error;
    }

    // derive AEK
    if(!derive_key((const sample_ec_dh_shared_t *)(&session->initiator.shared_key), SAMPLE_DERIVE_KEY_AEK, aek))
    {
        printf("derive aek error");
        se_ret = SAMPLE_ERROR_UNEXPECTED;
        goto error;
    }

    // clear session
    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    session->initiator.state = SGX_DH_SESSION_ACTIVE;

    // copy the common fields between REPORT and the responder enclave identity
    memcpy(responder_identity, &(((sgx_quote3_t*)msg3->msg3_body.quote_buffer)->report_body), sizeof(sgx_dh_session_enclave_identity_t));
    
    return SAMPLE_SUCCESS;

error:
    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    session->initiator.state = SGX_DH_SESSION_STATE_ERROR;
    INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret)
    return se_ret;
}

static sample_status_t dh_dcap_verify_message3(const sgx_dh_dcap_msg3_t *msg3,
                                       const sample_ec256_public_t *g_a,
                                       const sample_ec256_public_t *g_b,
                                       const sample_key_128bit_t *dh_smk)
{
    uint8_t* quote;
    uint32_t quote_size;
    uint32_t maced_size;
    sample_status_t se_ret;

    if(!msg3 || !g_a || !g_b || !dh_smk)
    {
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    maced_size = static_cast<uint32_t>(sizeof(sgx_dh_dcap_msg3_body_t));

    //Verify the MAC of message 3 obtained from the Session Responder
    if(!verify_cmac128(( uint8_t*)dh_smk, (const uint8_t*)&msg3->msg3_body, maced_size, msg3->cmac))
    {
        printf("MAC of message 3 obtained from the Session Responder mismatch");
        se_ret = SAMPLE_ERROR_UNEXPECTED;
        return se_ret;
    }
    printf("size of msg3 quote buffer %ld",sizeof(msg3->msg3_body.quote_buffer));
    memcpy(&quote_size, &msg3->msg3_body.quote_size, sizeof(uint32_t));
    quote = (uint8_t *)malloc(SGX_QUOTE3_BUFFER_SIZE);
    if(!quote)
        return SAMPLE_ERROR_OUT_OF_MEMORY;
    memcpy(quote, msg3->msg3_body.quote_buffer, msg3->msg3_body.quote_size);

    // Verify message 3 report
    int ret;
    ret = ecdsa_quote_verification(quote, quote_size);
    if(-1 == ret)
    {
        INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret);
        return se_ret;
    }

    return SAMPLE_SUCCESS;
}

#include "sgx_dcap_quoteverify.h"
#include "sgx_quote_3.h"

/**
 * @param quote - ECDSA quote buffer
 */

int ecdsa_quote_verification(uint8_t* quote, uint32_t quote_size)
{
    int ret = 0;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    uint32_t collateral_expiration_status = 1;

    printf("size of quote will be verified : %ld\n", quote_size);
    // Untrusted quote verification
    // call DCAP quote verify library to get supplemental data size
    //
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t))
    {
        printf("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
        p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
    }
    else
    {
        if (dcap_ret != SGX_QL_SUCCESS)
            printf("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);

        if (supplemental_data_size != sizeof(sgx_ql_qv_supplemental_t))
            printf("\tWarning: sgx_qv_get_quote_supplemental_data_size returned size is not same with header definition in SGX SDK, please make sure you are using same version of SGX SDK and DCAP QVL.\n");

        supplemental_data_size = 0;
    }

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    current_time = time(NULL);

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    dcap_ret = sgx_qv_verify_quote(
        (uint8_t*)quote, quote_size,
        NULL,
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        NULL,
        supplemental_data_size,
        p_supplemental_data);
    if (dcap_ret == SGX_QL_SUCCESS)
    {
        printf("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
    }
    else
    {
        printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
    }

    // check verification result
    //
    switch (quote_verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
        // check verification collateral expiration status
        // this value should be considered in your own attestation/verification policy
        //
        if (collateral_expiration_status == 0)
        {
            printf("\tInfo: App: Verification completed successfully.\n");
            ret = 0;
        }
        else
        {
            printf("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.\n");
            ret = 1;
        }
        break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        printf("\tWarning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
        ret = 1;
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        printf("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
        ret = -1;
        break;
    }

    // check supplemental data if necessary
    //
    if (p_supplemental_data != NULL && supplemental_data_size > 0)
    {
        sgx_ql_qv_supplemental_t *p = (sgx_ql_qv_supplemental_t *)p_supplemental_data;

        // you can check supplemental data based on your own attestation/verification policy
        // here we only print supplemental data version for demo usage
        //
        printf("\tInfo: Supplemental data version: %d\n", p->version);
    }

    return ret;
}

static sample_status_t dh_dcap_generate_message1(sgx_dh_dcap_msg1_t *msg1, sgx_internal_dh_session_t *context)
{
    sample_status_t se_ret;
    sample_ecc_state_handle_t ecc_state = NULL;

    if(!msg1 || !context)
    {
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    //Initialize ECC context to prepare for creating key pair
    se_ret = sample_ecc256_open_context(&ecc_state);
    if(se_ret != SAMPLE_SUCCESS)
    {
        return se_ret;
    }
    //Generate the public key private key pair for Session Responder
    se_ret = sample_ecc256_create_key_pair((sample_ec256_private_t*)&context->responder.prv_key,
                                       (sample_ec256_public_t*)&context->responder.pub_key,
                                       ecc_state);
    if(se_ret != SAMPLE_SUCCESS)
    {
         sample_ecc256_close_context(ecc_state);
         return se_ret;
    }

    //Copying public key to g^a
    memcpy(&msg1->g_a,
           &context->responder.pub_key,
           sizeof(sample_ec256_public_t));

    se_ret = sample_ecc256_close_context(ecc_state);
    if(SAMPLE_SUCCESS != se_ret)
    {
        return se_ret;
    }

    return SAMPLE_SUCCESS;
}

// Function sgx_dh_dcap_responder_gen_msg1 generates M1 message and makes update to the context of the session.
sample_status_t sgx_dh_dcap_responder_gen_msg1(sgx_dh_dcap_msg1_t* msg1, sgx_dh_session_t* sgx_dh_session)
{
    sample_status_t se_ret;
    sgx_internal_dh_session_t* session = (sgx_internal_dh_session_t*)sgx_dh_session;

    // validate session
    if(!session)
    {
        return SAMPLE_ERROR_INVALID_PARAMETER;
    }

    if(!msg1 ||
       SGX_DH_SESSION_RESPONDER != session->role)
    {
        se_ret = SAMPLE_ERROR_INVALID_PARAMETER;
        goto error;
    }

    if(SGX_DH_SESSION_STATE_RESET != session->responder.state)
    {
        printf("The state of responder session is not reset");
        se_ret = SAMPLE_ERROR_UNEXPECTED;
        goto error;
    }

    se_ret = dh_dcap_generate_message1(msg1, session);
    if(SAMPLE_SUCCESS != se_ret)
    {
        // return selected error to upper layer
        INTERNAL_SGX_ERROR_CODE_CONVERTOR(se_ret)
        goto error;
    }

    session->responder.state = SGX_DH_SESSION_RESPONDER_WAIT_M2;

    return SAMPLE_SUCCESS;
error:
    // clear session
    memset(session, 0, sizeof(sgx_internal_dh_session_t));
    session->responder.state = SGX_DH_SESSION_STATE_ERROR;
    return se_ret;
}