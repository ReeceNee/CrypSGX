/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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
#include "Enclave1_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E1.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include <map>

#define UNUSED(val) (void)(val)

std::map<sgx_enclave_id_t, dh_session_t> g_src_session_info_map;

uint8_t aes_key_now[KEY_LEN];
char aes_plaintext[CRPYTO_MSG_LEN];
char aes_ciphertext[CRPYTO_MSG_LEN];

static uint32_t e1_foo1_wrapper(ms_in_msg_exchange_t *ms, size_t param_lenth, char **resp_buffer, size_t *resp_length);

//Function pointer table containing the list of functions that the enclave exposes
const struct
{
    size_t num_funcs;
    const void *table[1];
} func_table = {
    1,
    {
        (const void *)e1_foo1_wrapper,
    }};

//Makes use of the sample code function to establish a secure channel with the destination enclave (Test Vector)
uint32_t test_create_session(sgx_enclave_id_t src_enclave_id,
                             sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    dh_session_t dest_session_info;

    //Core reference code function for creating a session
    ke_status = create_session(src_enclave_id, dest_enclave_id, &dest_session_info);

    //Insert the session information into the map under the corresponding destination enclave id
    if (ke_status == SUCCESS)
    {
        g_src_session_info_map.insert(std::pair<sgx_enclave_id_t, dh_session_t>(dest_enclave_id, dest_session_info));
    }
    memset(&dest_session_info, 0, sizeof(dh_session_t));
    return ke_status;
}

//Makes use of the sample code function to do an enclave to enclave call (Test Vector)
uint32_t test_enclave_to_enclave_call(sgx_enclave_id_t src_enclave_id,
                                      sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t var1, var2;
    uint32_t target_fn_id, msg_type;
    char *marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char *out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char *retval;

    var1 = 0x4;
    var2 = 0x5;
    target_fn_id = 0;
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = 50;

    //Marshals the input parameters for calling function foo1 in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_e2_foo1(target_fn_id, msg_type, var1, var2, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if (ke_status != SUCCESS)
    {
        return ke_status;
    }

    //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if (it != g_src_session_info_map.end())
    {
        dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                              marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);

    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the return value and output parameters from foo1 of Enclave 2
    ke_status = unmarshal_retval_and_output_parameters_e2_foo1(out_buff, &retval);
    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(retval);
    return SUCCESS;
}

//Makes use of the sample code function to do a generic secret message exchange (Test Vector)
uint32_t test_message_exchange(sgx_enclave_id_t src_enclave_id,
                               sgx_enclave_id_t dest_enclave_id)
{
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t target_fn_id, msg_type;
    char *marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char *out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char *secret_response;
    uint32_t secret_data;

    target_fn_id = 0;
    msg_type = MESSAGE_EXCHANGE;
    max_out_buff_size = 50;
    secret_data = 0x12345678; //Secret Data here is shown only for purpose of demonstration.

    //Marshals the secret data into a buffer
    ke_status = marshal_message_exchange_request(target_fn_id, msg_type, secret_data, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if (ke_status != SUCCESS)
    {
        return ke_status;
    }
    //Search the map for the session information associated with the destination enclave id passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if (it != g_src_session_info_map.end())
    {
        dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                              marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);
    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the secret response data
    ke_status = umarshal_message_exchange_response(out_buff, &secret_response);
    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(secret_response);
    return SUCCESS;
}

//Makes use of the sample code function to close a current session
uint32_t test_close_session(sgx_enclave_id_t src_enclave_id,
                            sgx_enclave_id_t dest_enclave_id)
{
    dh_session_t dest_session_info;
    ATTESTATION_STATUS ke_status = SUCCESS;
    //Search the map for the session information associated with the destination enclave id passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if (it != g_src_session_info_map.end())
    {
        dest_session_info = it->second;
    }
    else
    {
        return NULL;
    }

    //Core reference code function for closing a session
    ke_status = close_session(src_enclave_id, dest_enclave_id);

    //Erase the session information associated with the destination enclave id
    g_src_session_info_map.erase(dest_enclave_id);
    return ke_status;
}

//Function that is used to verify the trust of the other enclave
//Each enclave can have its own way verifying the peer enclave identity
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t *peer_enclave_identity)
{
    if (!peer_enclave_identity)
    {
        return INVALID_PARAMETER_ERROR;
    }
    if (peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
    // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
    {
        return ENCLAVE_TRUST_ERROR;
    }
    else
    {
        return SUCCESS;
    }
}

//Dispatcher function that calls the approriate enclave function based on the function id
//Each enclave can have its own way of dispatching the calls from other enclave
extern "C" uint32_t enclave_to_enclave_call_dispatcher(char *decrypted_data,
                                                       size_t decrypted_data_length,
                                                       char **resp_buffer,
                                                       size_t *resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t (*fn1)(ms_in_msg_exchange_t * ms, size_t, char **, size_t *);
    if (!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;
    if (ms->target_fn_id >= func_table.num_funcs)
    {
        return INVALID_PARAMETER_ERROR;
    }
    fn1 = (uint32_t(*)(ms_in_msg_exchange_t *, size_t, char **, size_t *))func_table.table[ms->target_fn_id];
    return fn1(ms, decrypted_data_length, resp_buffer, resp_length);
}

//Operates on the input secret and generates the output secret
uint32_t get_message_exchange_response(uint32_t inp_secret_data)
{
    uint32_t secret_response;

    //User should use more complex encryption method to protect their secret, below is just a simple example
    secret_response = inp_secret_data & 0x11111111;

    return secret_response;
}

//Generates the response from the request message
extern "C" uint32_t message_exchange_response_generator(char *decrypted_data,
                                                        char **resp_buffer,
                                                        size_t *resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t inp_secret_data;
    uint32_t out_secret_data;
    if (!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;

    if (umarshal_message_exchange_request(&inp_secret_data, ms) != SUCCESS)
        return ATTESTATION_ERROR;

    out_secret_data = get_message_exchange_response(inp_secret_data);

    if (marshal_message_exchange_response(resp_buffer, resp_length, out_secret_data) != SUCCESS)
        return MALLOC_ERROR;

    return SUCCESS;
}

static uint32_t e1_foo1(external_param_struct_t *p_struct_var)
{
    if (!p_struct_var)
    {
        return INVALID_PARAMETER_ERROR;
    }
    (p_struct_var->var1)++;
    (p_struct_var->var2)++;
    (p_struct_var->p_internal_struct->ivar1)++;
    (p_struct_var->p_internal_struct->ivar2)++;

    return (p_struct_var->var1 + p_struct_var->var2 + p_struct_var->p_internal_struct->ivar1 + p_struct_var->p_internal_struct->ivar2);
}

//Function which is executed on request from the source enclave
static uint32_t e1_foo1_wrapper(ms_in_msg_exchange_t *ms,
                                size_t param_lenth,
                                char **resp_buffer,
                                size_t *resp_length)
{
    UNUSED(param_lenth);

    uint32_t ret;
    size_t len_data, len_ptr_data;
    external_param_struct_t *p_struct_var;
    internal_param_struct_t internal_struct_var;

    if (!ms || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }

    p_struct_var = (external_param_struct_t *)malloc(sizeof(external_param_struct_t));
    if (!p_struct_var)
        return MALLOC_ERROR;

    p_struct_var->p_internal_struct = &internal_struct_var;

    if (unmarshal_input_parameters_e1_foo1(p_struct_var, ms) != SUCCESS) //can use the stack
    {
        SAFE_FREE(p_struct_var);
        return ATTESTATION_ERROR;
    }

    ret = e1_foo1(p_struct_var);

    len_data = sizeof(external_param_struct_t) - sizeof(p_struct_var->p_internal_struct);
    len_ptr_data = sizeof(internal_struct_var);

    if (marshal_retval_and_output_parameters_e1_foo1(resp_buffer, resp_length, ret, p_struct_var, len_data, len_ptr_data) != SUCCESS)
    {
        SAFE_FREE(p_struct_var);
        return MALLOC_ERROR;
    }
    SAFE_FREE(p_struct_var);
    return SUCCESS;
}

uint32_t set_enclave_aes_key(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, uint8_t *aes_key, uint32_t key_len)
{
    // copy aes_key to global aes_key_now
    memcpy(aes_key_now, aes_key, key_len);

    ATTESTATION_STATUS ke_status = SUCCESS;
    char *var1;
    uint32_t var2;
    uint32_t target_fn_id, msg_type;
    char *marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char *out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char *retval;

    var2 = key_len;
    var1 = (char *)malloc(var2);
    if (!var1)
        return MALLOC_ERROR;

    memcpy(var1, aes_key, key_len);
    // func_id 1 for e2_set_new_aes_key
    target_fn_id = 1;
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = 50;

    //Marshals the input parameters for calling function foo1 in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_e2_aes(target_fn_id, msg_type, (char *)var1, var2, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if (ke_status != SUCCESS)
    {
        return ke_status;
    }

    //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if (it != g_src_session_info_map.end())
    {
        dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                              marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);

    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the return value and output parameters from foo1 of Enclave 2
    ke_status = unmarshal_retval_and_output_parameters_e2_aes(out_buff, &retval);
    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(retval);
    return SUCCESS;
}

uint32_t encrypto_test(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, char *msg, uint32_t msg_len)
{
    // copy msg in global aes_plaintext
    strncpy(aes_plaintext, msg, msg_len);

    ATTESTATION_STATUS ke_status = SUCCESS;
    char *var1;
    uint32_t var2;
    uint32_t target_fn_id, msg_type;
    char *marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char *out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char *retval;

    var2 = msg_len;
    var1 = (char *)malloc(var2);
    if (!var1)
        return MALLOC_ERROR;

    memcpy(var1, msg, msg_len);
    // func_id 2 for encrypto_test
    target_fn_id = 2;
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = CRPYTO_MSG_LEN;

    //Marshals the input parameters for calling function foo1 in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_e2_aes(target_fn_id, msg_type, (char *)var1, var2, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if (ke_status != SUCCESS)
    {
        return ke_status;
    }

    //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if (it != g_src_session_info_map.end())
    {
        dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                              marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);

    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the return value and output parameters from foo1 of Enclave 2
    ke_status = unmarshal_retval_and_output_parameters_e2_aes(out_buff, &retval);
    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //check return value here (retval)
    sgx_status_t status;
    const uint8_t *p_add;
    uint32_t p_add_length;
    char *inp_buff = NULL;
    const sgx_aes_gcm_128bit_key_t *p_key;

    sgx_aes_gcm_data_t message_aes_gcm_data;
    p_add = (const uint8_t *)(" ");
    p_add_length = 0;

    inp_buff = aes_plaintext;
    const uint32_t data2encrypt_length = (uint32_t)msg_len;
    message_aes_gcm_data.payload_size = data2encrypt_length;
    p_key = (const sgx_aes_gcm_128bit_key_t *)aes_key_now;
    status = sgx_rijndael128GCM_encrypt(p_key, (uint8_t *)inp_buff, data2encrypt_length,
                                        reinterpret_cast<uint8_t *>(&(message_aes_gcm_data.payload)),
                                        message_aes_gcm_data.reserved,
                                        sizeof(message_aes_gcm_data.reserved), p_add, p_add_length,
                                        &message_aes_gcm_data.payload_tag);
    if (SGX_SUCCESS != status)
    {
        // SAFE_FREE(message_aes_gcm_data);
        return status;
    }

    char *rst_local = (char *)message_aes_gcm_data.payload;
    int cmp_result = memcmp(rst_local, retval, message_aes_gcm_data.payload_size);

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(retval);
    return SUCCESS;
}

uint32_t decrypto_test(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, char *msg, uint32_t msg_len)
{
    // copy msg in global aes_ciphertext
    strncpy(aes_ciphertext, msg, msg_len);

    ATTESTATION_STATUS ke_status = SUCCESS;
    char *var1;
    uint32_t var2;
    uint32_t target_fn_id, msg_type;
    char *marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char *out_buff;
    size_t out_buff_len;
    dh_session_t *dest_session_info;
    size_t max_out_buff_size;
    char *retval;

    var2 = msg_len;
    var1 = (char *)malloc(var2);
    if (!var1)
        return MALLOC_ERROR;

    memcpy(var1, msg, msg_len);
    // func_id 3 for decrypto_test
    target_fn_id = 3;
    msg_type = ENCLAVE_TO_ENCLAVE_CALL;
    max_out_buff_size = CRPYTO_MSG_LEN;

    //Marshals the input parameters for calling function foo1 in Enclave2 into a input buffer
    ke_status = marshal_input_parameters_e2_aes(target_fn_id, msg_type, (char *)var1, var2, &marshalled_inp_buff, &marshalled_inp_buff_len);
    if (ke_status != SUCCESS)
    {
        return ke_status;
    }

    //Search the map for the session information associated with the destination enclave id of Enclave2 passed in
    std::map<sgx_enclave_id_t, dh_session_t>::iterator it = g_src_session_info_map.find(dest_enclave_id);
    if (it != g_src_session_info_map.end())
    {
        dest_session_info = &it->second;
    }
    else
    {
        SAFE_FREE(marshalled_inp_buff);
        return INVALID_SESSION;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(src_enclave_id, dest_enclave_id, dest_session_info, marshalled_inp_buff,
                                              marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);

    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the return value and output parameters from foo1 of Enclave 2
    ke_status = unmarshal_retval_and_output_parameters_e2_aes(out_buff, &retval);
    if (ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //check return value here (retval)
    sgx_status_t status;
    const uint8_t *p_add;
    uint32_t p_add_length;
    char *inp_buff = NULL;
    const sgx_aes_gcm_128bit_key_t *p_key;

    sgx_aes_gcm_data_t message_aes_gcm_data;
    p_add = (const uint8_t *)(" ");
    p_add_length = 0;

    inp_buff = aes_ciphertext;
    const uint32_t data2decrypt_length = (uint32_t)msg_len;
    message_aes_gcm_data.payload_size = data2decrypt_length;
    p_key = (const sgx_aes_gcm_128bit_key_t *)aes_key_now;
    status = sgx_rijndael128GCM_decrypt(p_key, (uint8_t *)inp_buff, data2decrypt_length,
                                        reinterpret_cast<uint8_t *>(&(message_aes_gcm_data.payload)),
                                        message_aes_gcm_data.reserved,
                                        sizeof(message_aes_gcm_data.reserved), p_add, p_add_length,
                                        &message_aes_gcm_data.payload_tag);
    if (SGX_SUCCESS != status)
    {
        // SAFE_FREE(message_aes_gcm_data);
        return status;
    }

    char *rst_local = (char *)message_aes_gcm_data.payload;
    int cmp_result = memcmp(rst_local, retval, message_aes_gcm_data.payload_size);

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(retval);
    return SUCCESS;
}
