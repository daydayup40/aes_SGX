#include "aes_SGX_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_AES_ECB_encrypt(void* pms)
{
	ms_AES_ECB_encrypt_t* ms = SGX_CAST(ms_AES_ECB_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_input = ms->ms_input;
	uint32_t _tmp_length = ms->ms_length;
	size_t _len_input = _tmp_length;
	uint8_t* _in_input = NULL;
	uint8_t* _tmp_key = ms->ms_key;
	size_t _len_key = 16;
	uint8_t* _in_key = NULL;
	uint8_t* _tmp_output = ms->ms_output;

	CHECK_REF_POINTER(pms, sizeof(ms_AES_ECB_encrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	if (_tmp_input != NULL) {
		_in_input = (uint8_t*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_key != NULL) {
		_in_key = (uint8_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	AES_ECB_encrypt(_in_input, _in_key, _tmp_output, _tmp_length);
err:
	if (_in_input) free(_in_input);
	if (_in_key) free(_in_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_AES_ECB_decrypt(void* pms)
{
	ms_AES_ECB_decrypt_t* ms = SGX_CAST(ms_AES_ECB_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_input = ms->ms_input;
	uint32_t _tmp_length = ms->ms_length;
	size_t _len_input = _tmp_length;
	uint8_t* _in_input = NULL;
	uint8_t* _tmp_key = ms->ms_key;
	size_t _len_key = 16;
	uint8_t* _in_key = NULL;
	uint8_t* _tmp_output = ms->ms_output;

	CHECK_REF_POINTER(pms, sizeof(ms_AES_ECB_decrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	if (_tmp_input != NULL) {
		_in_input = (uint8_t*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_key != NULL) {
		_in_key = (uint8_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	AES_ECB_decrypt(_in_input, _in_key, _tmp_output, _tmp_length);
err:
	if (_in_input) free(_in_input);
	if (_in_key) free(_in_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_AES_CBC_encrypt_buffer(void* pms)
{
	ms_AES_CBC_encrypt_buffer_t* ms = SGX_CAST(ms_AES_CBC_encrypt_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_output = ms->ms_output;
	uint8_t* _tmp_input = ms->ms_input;
	uint32_t _tmp_length = ms->ms_length;
	size_t _len_input = _tmp_length;
	uint8_t* _in_input = NULL;
	uint8_t* _tmp_key = ms->ms_key;
	size_t _len_key = 16;
	uint8_t* _in_key = NULL;
	uint8_t* _tmp_iv = ms->ms_iv;
	size_t _len_iv = 16;
	uint8_t* _in_iv = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_AES_CBC_encrypt_buffer_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);

	if (_tmp_input != NULL) {
		_in_input = (uint8_t*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_key != NULL) {
		_in_key = (uint8_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	if (_tmp_iv != NULL) {
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_iv, _tmp_iv, _len_iv);
	}
	AES_CBC_encrypt_buffer(_tmp_output, _in_input, _tmp_length, _in_key, _in_iv);
err:
	if (_in_input) free(_in_input);
	if (_in_key) free(_in_key);
	if (_in_iv) free(_in_iv);

	return status;
}

static sgx_status_t SGX_CDECL sgx_AES_CBC_decrypt_buffer(void* pms)
{
	ms_AES_CBC_decrypt_buffer_t* ms = SGX_CAST(ms_AES_CBC_decrypt_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_output = ms->ms_output;
	uint8_t* _tmp_input = ms->ms_input;
	uint32_t _tmp_length = ms->ms_length;
	size_t _len_input = _tmp_length;
	uint8_t* _in_input = NULL;
	uint8_t* _tmp_key = ms->ms_key;
	size_t _len_key = 16;
	uint8_t* _in_key = NULL;
	uint8_t* _tmp_iv = ms->ms_iv;
	size_t _len_iv = 16;
	uint8_t* _in_iv = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_AES_CBC_decrypt_buffer_t));
	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);

	if (_tmp_input != NULL) {
		_in_input = (uint8_t*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_input, _tmp_input, _len_input);
	}
	if (_tmp_key != NULL) {
		_in_key = (uint8_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_key, _tmp_key, _len_key);
	}
	if (_tmp_iv != NULL) {
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_iv, _tmp_iv, _len_iv);
	}
	AES_CBC_decrypt_buffer(_tmp_output, _in_input, _tmp_length, _in_key, _in_iv);
err:
	if (_in_input) free(_in_input);
	if (_in_key) free(_in_key);
	if (_in_iv) free(_in_iv);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_AES_ECB_encrypt, 0},
		{(void*)(uintptr_t)sgx_AES_ECB_decrypt, 0},
		{(void*)(uintptr_t)sgx_AES_CBC_encrypt_buffer, 0},
		{(void*)(uintptr_t)sgx_AES_CBC_decrypt_buffer, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][4];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(0, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
