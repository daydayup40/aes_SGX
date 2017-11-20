#include "aes_SGX_u.h"
#include <errno.h>

typedef struct ms_AES_ECB_encrypt_t {
	uint8_t* ms_input;
	uint8_t* ms_key;
	uint8_t* ms_output;
	uint32_t ms_length;
} ms_AES_ECB_encrypt_t;

typedef struct ms_AES_ECB_decrypt_t {
	uint8_t* ms_input;
	uint8_t* ms_key;
	uint8_t* ms_output;
	uint32_t ms_length;
} ms_AES_ECB_decrypt_t;

typedef struct ms_AES_CBC_encrypt_buffer_t {
	uint8_t* ms_output;
	uint8_t* ms_input;
	uint32_t ms_length;
	uint8_t* ms_key;
	uint8_t* ms_iv;
} ms_AES_CBC_encrypt_buffer_t;

typedef struct ms_AES_CBC_decrypt_buffer_t {
	uint8_t* ms_output;
	uint8_t* ms_input;
	uint32_t ms_length;
	uint8_t* ms_key;
	uint8_t* ms_iv;
} ms_AES_CBC_decrypt_buffer_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL aes_SGX_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL aes_SGX_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL aes_SGX_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL aes_SGX_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL aes_SGX_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[5];
} ocall_table_aes_SGX = {
	5,
	{
		(void*)(uintptr_t)aes_SGX_sgx_oc_cpuidex,
		(void*)(uintptr_t)aes_SGX_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)aes_SGX_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)aes_SGX_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)aes_SGX_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t AES_ECB_encrypt(sgx_enclave_id_t eid, uint8_t* input, uint8_t* key, uint8_t* output, uint32_t length)
{
	sgx_status_t status;
	ms_AES_ECB_encrypt_t ms;
	ms.ms_input = input;
	ms.ms_key = key;
	ms.ms_output = output;
	ms.ms_length = length;
	status = sgx_ecall(eid, 0, &ocall_table_aes_SGX, &ms);
	return status;
}

sgx_status_t AES_ECB_decrypt(sgx_enclave_id_t eid, uint8_t* input, uint8_t* key, uint8_t* output, uint32_t length)
{
	sgx_status_t status;
	ms_AES_ECB_decrypt_t ms;
	ms.ms_input = input;
	ms.ms_key = key;
	ms.ms_output = output;
	ms.ms_length = length;
	status = sgx_ecall(eid, 1, &ocall_table_aes_SGX, &ms);
	return status;
}

sgx_status_t AES_CBC_encrypt_buffer(sgx_enclave_id_t eid, uint8_t* output, uint8_t* input, uint32_t length, uint8_t* key, uint8_t* iv)
{
	sgx_status_t status;
	ms_AES_CBC_encrypt_buffer_t ms;
	ms.ms_output = output;
	ms.ms_input = input;
	ms.ms_length = length;
	ms.ms_key = key;
	ms.ms_iv = iv;
	status = sgx_ecall(eid, 2, &ocall_table_aes_SGX, &ms);
	return status;
}

sgx_status_t AES_CBC_decrypt_buffer(sgx_enclave_id_t eid, uint8_t* output, uint8_t* input, uint32_t length, uint8_t* key, uint8_t* iv)
{
	sgx_status_t status;
	ms_AES_CBC_decrypt_buffer_t ms;
	ms.ms_output = output;
	ms.ms_input = input;
	ms.ms_length = length;
	ms.ms_key = key;
	ms.ms_iv = iv;
	status = sgx_ecall(eid, 3, &ocall_table_aes_SGX, &ms);
	return status;
}

