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

// App.cpp : Defines the entry point for the console application.
#include <stdio.h>
#include <map>
#include "../Enclave1/Enclave1_u.h"
#include "../Enclave2/Enclave2_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define UNUSED(val) (void)(val)
#define TCHAR char
#define _TCHAR char
#define _T(str) str
#define scanf_s scanf
#define _tmain main

extern std::map<sgx_enclave_id_t, uint32_t> g_enclave_id_map;

sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;

#define ENCLAVE1_PATH "libenclave1.so"
#define ENCLAVE2_PATH "libenclave2.so"

//global vars
char aes_key[KEY_LEN];

void waitForKeyPress()
{
    char ch;
    int temp;
    printf("\n\nHit a key....\n");
    temp = scanf_s("%c", &ch);
}

uint32_t load_enclaves()
{
    uint32_t enclave_temp_no;
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e1_enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));

    return SGX_SUCCESS;
}

int show_menu()
{
    printf("\n************OPTIONS************\n");
    printf("1.Set a new Key\n");
    printf("2.Encryption Test\n");
    printf("3.Decryption Test\n");
    printf("0.Exit\n");
    printf("Give your choice(0-3):");

    int tmp;
    scanf("%d", &tmp);
    if (tmp < 0 || tmp > 3)
        tmp = -1;
    return tmp;
}

bool set_new_aes_key()
{
    uint32_t ret_status;
    sgx_status_t status;

    bool runFlag = false;

    char key_now[KEY_LEN] = "aaaaaaaabbbbbbbbccccccccdddddddd";

    strncpy(aes_key, key_now, KEY_LEN);
    printf("The key is :%s\n", aes_key);
    status = Enclave1_set_enclave_aes_key(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id, aes_key, KEY_LEN);
    if (status != SGX_SUCCESS)
    {
        printf("Enclave1_set_enclave_aes_key Ecall failed: Error code is %x", status);
    }
    else
    {
        if (ret_status == 0)
        {
            printf("\n\nSet AES KEY from clent(Enclave 1) to Server(Enclave 2) successful !!!");
            runFlag = true;
        }
        else
        {
            printf("\nSession establishment and key exchange failure between  clent(Enclave 1) and Server(Enclave 2): Error code is %x", ret_status);
        }
    }
    return runFlag;
}

int _tmain(int argc, _TCHAR *argv[])
{
    uint32_t ret_status;
    sgx_status_t status;

    UNUSED(argc);
    UNUSED(argv);

    if (load_enclaves() != SGX_SUCCESS)
    {
        printf("\nLoad Enclave Failure");
    }

    printf("\nAvailable Enclaves");
    printf("\nEnclave1 - EnclaveID %" PRIx64, e1_enclave_id);
    printf("\nEnclave2 - EnclaveID %" PRIx64, e2_enclave_id);

    do
    {
        //Test Create session between Enclave1(Source) and Enclave2(Destination)
        status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
        if (status != SGX_SUCCESS)
        {
            printf("Enclave1_test_create_session Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if (ret_status == 0)
            {
                printf("\n\nSecure Channel Establishment between clent(Enclave 1) and Server(Enclave 2) Enclaves successful !!!");
            }
            else
            {
                printf("\nSession establishment and key exchange failure between clent(Enclave 1) and Server(Enclave 2): Error code is %x", ret_status);
                break;
            }
        }

        //Test Enclave to Enclave call between Enclave1(Source) and Enclave2(Destination)
        status = Enclave1_test_enclave_to_enclave_call(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
        if (status != SGX_SUCCESS)
        {
            printf("Enclave1_test_enclave_to_enclave_call Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if (ret_status == 0)
            {
                printf("\n\nEnclave to Enclave Call between clent(Enclave 1) and Server(Enclave 2) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nEnclave to Enclave Call failure between clent(Enclave 1) and Server(Enclave 2): Error code is %x", ret_status);
                break;
            }
        }
        //Test message exchange between Enclave1(Source) and Enclave2(Destination)
        status = Enclave1_test_message_exchange(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
        if (status != SGX_SUCCESS)
        {
            printf("Enclave1_test_message_exchange Ecall failed: Error code is %x", status);
            break;
        }
        else
        {
            if (ret_status == 0)
            {
                printf("\n\nMessage Exchange between clent(Enclave 1) and Server(Enclave 2) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nMessage Exchange failure between clent(Enclave 1) and Server(Enclave 2): Error code is %x", ret_status);
                break;
            }
        }

        //Main menu for ctypto test
        int chi;
        bool runFlag = true;
        while (runFlag)
        {
            chi = show_menu();
            switch (chi)
            {
            case 0:
                runFlag = false;

            case 1:
                runFlag = set_new_aes_key();
            case 2:
                continue;
            case 3:
                continue;
            default:
                printf("Wrong choice!\n");
                continue;
            }
        }

#pragma warning(push)
#pragma warning(disable : 4127)
    } while (0);
#pragma warning(pop)

    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);

    waitForKeyPress();

    return 0;
}
