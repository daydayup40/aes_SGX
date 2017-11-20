#ifndef AES_SGX_U_H__
#define AES_SGX_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t AES_ECB_encrypt(sgx_enclave_id_t eid, uint8_t* input, uint8_t* key, uint8_t* output, uint32_t length);
sgx_status_t AES_ECB_decrypt(sgx_enclave_id_t eid, uint8_t* input, uint8_t* key, uint8_t* output, uint32_t length);
sgx_status_t AES_CBC_encrypt_buffer(sgx_enclave_id_t eid, uint8_t* output, uint8_t* input, uint32_t length, uint8_t* key, uint8_t* iv);
sgx_status_t AES_CBC_decrypt_buffer(sgx_enclave_id_t eid, uint8_t* output, uint8_t* input, uint32_t length, uint8_t* key, uint8_t* iv);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
