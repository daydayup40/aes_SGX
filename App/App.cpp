// App.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "aes_SGX_u.h"
#include "sgx_capable.h"
#include "sgx_uae_service.h"
#include "sgx_tcrypto.h"
#include "sgx_urts.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ENCLAVE_FILE _T("aes_SGX.signed.dll")

sgx_enclave_id_t enclaveId = NULL;
sgx_launch_token_t token = { 0 };
int updated;

bool initializeEnclave()
{
	if (sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated,
		&enclaveId, NULL) != SGX_SUCCESS)
		//printf("Error %#x: cannot create enclave\n", ret);
		return false;
	return true;
}
bool destroyEnclave()
{
	if (sgx_destroy_enclave(enclaveId) != SGX_SUCCESS)
		//printf("Error %x: cant destroy enclave\n", ret);
		return false;
	return true;
}
void printHex(uint8_t* data, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		if (data[i] < 0x10)
		{
			printf("0%1x", data[i]);
		}
		else
		{
			printf("%2x", data[i]);
		}
		
	}
	printf("\n");
}
void testAESEBC()
{
	printf("aes_ebc sgx test\n");
	uint8_t key[16] = { (uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16, (uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6, (uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88, (uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c };
	// 512bit text
	uint8_t plain_text[64] = { (uint8_t)0x6b, (uint8_t)0xc1, (uint8_t)0xbe, (uint8_t)0xe2, (uint8_t)0x2e, (uint8_t)0x40, (uint8_t)0x9f, (uint8_t)0x96, (uint8_t)0xe9, (uint8_t)0x3d, (uint8_t)0x7e, (uint8_t)0x11, (uint8_t)0x73, (uint8_t)0x93, (uint8_t)0x17, (uint8_t)0x2a,
		(uint8_t)0xae, (uint8_t)0x2d, (uint8_t)0x8a, (uint8_t)0x57, (uint8_t)0x1e, (uint8_t)0x03, (uint8_t)0xac, (uint8_t)0x9c, (uint8_t)0x9e, (uint8_t)0xb7, (uint8_t)0x6f, (uint8_t)0xac, (uint8_t)0x45, (uint8_t)0xaf, (uint8_t)0x8e, (uint8_t)0x51,
		(uint8_t)0x30, (uint8_t)0xc8, (uint8_t)0x1c, (uint8_t)0x46, (uint8_t)0xa3, (uint8_t)0x5c, (uint8_t)0xe4, (uint8_t)0x11, (uint8_t)0xe5, (uint8_t)0xfb, (uint8_t)0xc1, (uint8_t)0x19, (uint8_t)0x1a, (uint8_t)0x0a, (uint8_t)0x52, (uint8_t)0xef,
		(uint8_t)0xf6, (uint8_t)0x9f, (uint8_t)0x24, (uint8_t)0x45, (uint8_t)0xdf, (uint8_t)0x4f, (uint8_t)0x9b, (uint8_t)0x17, (uint8_t)0xad, (uint8_t)0x2b, (uint8_t)0x41, (uint8_t)0x7b, (uint8_t)0xe6, (uint8_t)0x6c, (uint8_t)0x37, (uint8_t)0x10 };

	printf("key : ");
	printHex(key, 16);
	printf("text : ");
	printHex(plain_text, 64);
	uint8_t buf[64], buf2[64];
	AES_ECB_encrypt(enclaveId, plain_text, key, buf, 64);
	printf("encrypted text : ");
	printHex(buf, 64);
	AES_ECB_decrypt(enclaveId, buf, key, buf2, 64);
	printf("decrypted text : ");
	printHex(buf2, 64);
}

void testAESCBC()
{
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t plain_text[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
		0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
		0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
		0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
	uint8_t  iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	printf("key : ");
	printHex(key, 16);
	printf("text : ");
	printHex(plain_text, 64);
	uint8_t buf[64], buf2[64];
	AES_CBC_encrypt_buffer(enclaveId, buf, plain_text, 64, key, iv);
	printf("encrypted text : ");
	printHex(buf, 64);
	AES_CBC_decrypt_buffer(enclaveId, buf2, buf, 64, key,iv);
	printf("decrypted text : ");
	printHex(buf2, 64);
}

int main()
{
	sgx_status_t ret = SGX_SUCCESS;
	if (!initializeEnclave())
	{
		printf("init failed!\n");
		return -1;
	}
	testAESEBC();

	testAESCBC();

	if (!destroyEnclave())
	{
		printf("failed to destory sgx\n");
		return -1;
	}
	printf("hahaha\n");
	system("pause");
    return 0;
}

