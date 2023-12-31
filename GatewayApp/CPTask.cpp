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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <map>
#include <sys/stat.h>
#include <sched.h>

#include "GatewayEnclave_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"

#include "cpdef.h"
#include "fifo_def.h"
#include "datatypes.h"

#include "CPTask.h"
#include "CPServer.h"

sgx_enclave_id_t e2_enclave_id = 0;
sgx_enclave_id_t wasm_vm_enclave_id[3] = { 1, 2, 3};
#define GATEWAY_ENCLAVE_NAME "libgateway_enclave.signed.so"

/* Function Description:
 *  This function responds to initiator enclave's connection request by generating and sending back ECDH message 1
 * Parameter Description:
 *  [input] clientfd: this is client's connection id. After generating ECDH message 1, server would send back response through this connection id.
 * */
int generate_and_send_session_msg1_resp(int clientfd)
{
    int retcode = 0;
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    SESSION_MSG1_RESP msg1resp;
    FIFO_MSG * fifo_resp = NULL;
    size_t respmsgsize;

    memset(&msg1resp, 0, sizeof(SESSION_MSG1_RESP));

    // call gateway enclave to generate ECDH message 1
    ret = session_request(e2_enclave_id, &status, &msg1resp.dh_msg1, &msg1resp.sessionid);
    if ((ret != SGX_SUCCESS) || (status != SGX_SUCCESS))
    {
        printf("failed to do ECALL session_request.\n");
        return -1;
    }
    
    respmsgsize = sizeof(FIFO_MSG) + sizeof(SESSION_MSG1_RESP);
    fifo_resp = (FIFO_MSG *)malloc(respmsgsize);
    if (!fifo_resp)
    {
        printf("memory allocation failure.\n");
        return -1;
    }
    memset(fifo_resp, 0, respmsgsize);

    fifo_resp->header.type = FIFO_DH_RESP_MSG1;
    fifo_resp->header.size = sizeof(SESSION_MSG1_RESP);
    
    memcpy(fifo_resp->msgbuf, &msg1resp, sizeof(SESSION_MSG1_RESP));
    
    //send message 1 to client
    if (send(clientfd, reinterpret_cast<char *>(fifo_resp), static_cast<int>(respmsgsize), 0) == -1)
    {
        printf("fail to send msg1 response.\n");
        retcode = -1;
    }
    free(fifo_resp);
    return retcode;
}

/* Function Description:
 *  This function process ECDH message 2 received from client and send message 3 to client
 * Parameter Description:
 *  [input] clientfd: this is client's connection id
 *  [input] msg2: this contains ECDH message 2 received from client
 * */
int process_exchange_report(int clientfd, SESSION_MSG2 * msg2)
{
    uint32_t status = 0;
        sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG *response;
    SESSION_MSG3 * msg3;
    size_t msgsize;
    
    if (!msg2)
        return -1;
    
    msgsize = sizeof(FIFO_MSG_HEADER) + sizeof(SESSION_MSG3);
    response = (FIFO_MSG *)malloc(msgsize);
    if (!response)
    {
        printf("memory allocation failure\n");
        return -1;
    }
    memset(response, 0, msgsize);
    
    response->header.type = FIFO_DH_MSG3;
    response->header.size = sizeof(SESSION_MSG3);
    
    msg3 = (SESSION_MSG3 *)response->msgbuf;
    msg3->sessionid = msg2->sessionid; 

    // call gateway enclave to process ECDH message 2 and generate message 3
    ret = exchange_report(e2_enclave_id, &status, &msg2->dh_msg2, &msg3->dh_msg3, msg2->sessionid);
    if (ret != SGX_SUCCESS)
    {
        printf("EnclaveResponse_exchange_report failure.\n");
        free(response);
        return -1;
    }
    
    // send ECDH message 3 to client
    if (send(clientfd, reinterpret_cast<char *>(response), static_cast<int>(msgsize), 0) == -1)
    {
        printf("server_send() failure.\n");
        free(response);
        return -1;
    }

    free(response);

    return 0;
}

/* Function Description:
 *  This function process received message communication from client
 * Parameter Description:
 *  [input] clientfd: this is client's connection id
 *  [input] req_msg: this is pointer to received message from client
 * */
int process_msg_transfer(int clientfd, FIFO_MSGBODY_REQ *req_msg)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    secure_message_t *resp_message = NULL;
    FIFO_MSG * fifo_resp = NULL;
    size_t resp_message_size;
    if (!req_msg)
    {
        printf("invalid parameter.\n");
        return -1;
    }

    resp_message_size = sizeof(secure_message_t) + req_msg->max_payload_size;
    printf("req->session_id = %d\n", req_msg->session_id);
    //Allocate memory for the response message
    printf("req->max_payload_size = %d\n", req_msg->max_payload_size);
    printf("req->size = %d\n", req_msg->size);
    resp_message = (secure_message_t*)malloc(resp_message_size);
    if (!resp_message)
    {
        printf("Gateway Enclave: memory allocation failure.\n");
        return -1;
    }
    memset(resp_message, 0, resp_message_size);
    ret = generate_response(e2_enclave_id, &status, (secure_message_t *)req_msg->buf, req_msg->size, req_msg->max_payload_size, resp_message, &resp_message_size, req_msg->session_id);
    if (ret != SGX_SUCCESS)
    {
        printf("Gateway Enclave: ecall generate_response error. ret = %d, e2_enclave_id = %d\n", ret, e2_enclave_id);
        free(resp_message);
        return -1;
    }
    if (status != 0) {
        printf("Gateway Enclave: generate_response error. ret = %d\n", status);
        free(resp_message);
        return -1;
    }

    fifo_resp = (FIFO_MSG *)malloc(sizeof(FIFO_MSG) + resp_message_size - 1);
    if (!fifo_resp)
    {
        printf("memory allocation failure.\n");
        free(resp_message);
        return -1;
    }
    memset(fifo_resp, 0, sizeof(FIFO_MSG) + resp_message_size - 1);
    printf("fifo_resp.size = %lld\n", sizeof(FIFO_MSG) + resp_message_size);

    fifo_resp->header.type = FIFO_DH_MSG_RESP;
    fifo_resp->header.size = resp_message_size + 20;
    memcpy(fifo_resp->msgbuf, resp_message, resp_message_size);

    free(resp_message);
    printf("send.size = %lld\n", sizeof(FIFO_MSG) + static_cast<int>(resp_message_size) - 1);
    printf("resp_message_size = %lld\n", static_cast<int>(resp_message_size) - 1);
    printf("FIFO_MSG size = %lld\n", sizeof(FIFO_MSG));

    if (send(clientfd, reinterpret_cast<char *>(fifo_resp), sizeof(FIFO_MSG) + static_cast<int>(resp_message_size)  - 1, 0) == -1)
    {
        printf("server_send() failure.\n");
        free(fifo_resp);
        return -1;
    }
    free(fifo_resp);

    return 0;
}

/* Function Description: This is process session close request from client
 * Parameter Description:
 *  [input] clientfd: this is client connection id
 *  [input] close_req: this is pointer to client's session close request
 * */
int process_close_req(int clientfd, SESSION_CLOSE_REQ * close_req)
{
    uint32_t status = 0;
    sgx_status_t ret = SGX_SUCCESS;
    FIFO_MSG close_ack;
    
    if (!close_req)
        return -1; 

    // call gateway enclave to close this session
    ret = end_session(e2_enclave_id, &status, close_req->session_id);
    if (ret != SGX_SUCCESS)
        return -1;

    // send back response
    close_ack.header.type = FIFO_DH_CLOSE_RESP;
    close_ack.header.size = 0;

    if (send(clientfd, reinterpret_cast<char *>(&close_ack), sizeof(FIFO_MSG), 0) == -1)
    {
        printf("server_send() failure.\n");
        return -1;
    }

    return 0;
}

#include <ctime>

uint64_t
time_diff(struct timespec *ts1, struct timespec *ts2) {
    uint64_t t1;
    uint64_t t2;

    t1 = ts1->tv_sec * 1000000000 + ts1->tv_nsec;
    t2 = ts2->tv_sec * 1000000000 + ts2->tv_nsec;
    return t2 - t1;
}

void CPTask::run()
{
    FIFO_MSG * message = NULL;
    sgx_launch_token_t token = {0};
    sgx_status_t status;
    int update = 0;
    struct timespec ts1;
    struct timespec ts2;

    // load gateway enclave 
    status = sgx_create_enclave(GATEWAY_ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &update, &e2_enclave_id, NULL);
    if (status != SGX_SUCCESS)
    {
        printf("failed to load enclave %s, error code is 0x%x.\n", GATEWAY_ENCLAVE_NAME, status);
        return;
    }
    printf("enclave id is %d\n", e2_enclave_id);
    // create ECDH session using gateway enclave, it would create ECDH session with wasm vm enclave running in another process
    // Time of test_create_session is the DCAP overhead
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts1);
    status = test_create_session(e2_enclave_id, (uint32_t *)&status, wasm_vm_enclave_id[0]);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts2);
    printf("Gateway App: DCAP took %ld\n", time_diff(&ts1, &ts2));
    if (status != SGX_SUCCESS || status != 0)
    {
        printf("failed to establish secure channel: ECALL return 0x%x, error code is 0x%x.\n", status, status);
        return;
    }
    printf("Succeed to establish secure channel with wasm vm enclave.\n");

    while (!isStopped())
    {
        /* receive task frome queue */
        message  = m_queue.blockingPop();
        if (isStopped())
        {
            free(message);
            break;
        }
        int clientfd = message->header.sockfd;

        switch (message->header.type)
        {
            case FIFO_DH_REQ_MSG1:
            {
                // process ECDH session connection request
                printf("process ECDH session connection request\n");
                if (generate_and_send_session_msg1_resp(clientfd) != 0)
                {
                    printf("failed to generate and send session msg1 resp.\n");
                    break;
                }
                printf("process ECDH session connection request success\n");
            }
            break;

            case FIFO_DH_MSG2:
            {
                // process ECDH message 2
                printf("process ECDH message 2\n");
                SESSION_MSG2 * msg2 = NULL;
                msg2 = (SESSION_MSG2 *)message->msgbuf;

                if (process_exchange_report(clientfd, msg2) != 0)
                {
                    printf("failed to process exchange_report request.\n");
                    break;
                }
                printf("process ECDH message 2 success\n");
            }
            break;

            case FIFO_DH_MSG_REQ:
            {
                // process message transfer request
                printf("process message transfer request\n");
                FIFO_MSGBODY_REQ *msg = NULL;
                msg = (FIFO_MSGBODY_REQ *)message->msgbuf;
                if (process_msg_transfer(clientfd, msg) != 0)   
                {
                    printf("failed to process message transfer request.\n");
                    break;
                }
                printf("process message transfer request success\n");       
            }
            break;

            case FIFO_DH_CLOSE_REQ:
            {
                printf("process message close request\n"); 
                // process message close request
                SESSION_CLOSE_REQ * closereq = NULL;

                closereq = (SESSION_CLOSE_REQ *)message->msgbuf;

                process_close_req(clientfd, closereq);
                printf("process message close request success\n"); 

                // close ECDH session
                status = test_close_session(e2_enclave_id, (uint32_t *)&status, wasm_vm_enclave_id[0]);
                if (status != SGX_SUCCESS || status != 0)
                {
                    printf("test_close_session Ecall failed: ECALL return 0x%x, error code is 0x%x.\n", status, status);
                    return;
                }
                printf("Succeed to close Session with wasm vm enclave...\n");
            }
            break;
        default:
            {
                printf("Unknown message.\n");
		 printf("Type: %08X\n", message->header.type);
            }
            break;
        }

        //free(message);
        //message = NULL;
        
        close(clientfd);
        printf("client %d closed\n", clientfd);
    }

    sgx_destroy_enclave(e2_enclave_id);
}

void CPTask::shutdown()
{
    stop();
    m_queue.close();
    join();
}

void CPTask::puttask(FIFO_MSG* requestData)
{
    if (isStopped()) {
        return;
    }
    
    m_queue.push(requestData);
}

