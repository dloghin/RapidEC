#include "hbdb_interface.h"
#include "gsv_wrapper.h"
#include "keccak_gpu.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

gsv_verify_t *sig;
int* res;
unsigned char* cres;

void init_gpu(int num) {
    GSV_verify_init(1);
    keccak_init(num);
    sig = (gsv_verify_t *)malloc(sizeof(gsv_verify_t) * num);
    if (!sig) {
        printf("Error in allocating signatures!\n");
        return;
    }
    res = (int*)malloc(num * sizeof(int));
    if (!res) {
        printf("Error in allocating results!\n");
        return;
    }
    cres = (unsigned char*)malloc(num * sizeof(unsigned char));
    if (!cres) {
        printf("Error in allocating byte results!\n");
        return;
    }
}
    
int run_kernel(unsigned char* data, int* sizes, unsigned char* keys, unsigned char* signatures, int num) {
    keccak_kernel(data, sizes, num);
    unsigned char* dig = keccak_get_results(num);
    for (int i = 0; i < num; i++) {
        memcpy(&(sig[i].r), signatures + (i * 64), 32);
        memcpy(&(sig[i].s), signatures + (i * 64 + 32), 32);
        memcpy(&(sig[i].key_x), keys + (i * 64), 32);
        memcpy(&(sig[i].key_y), keys + (i * 64 + 32), 32);
        memcpy(&(sig[i].e), dig + (i * 32), 32);
    }
    GSV_verify_exec(1, num, sig, res);
}

unsigned char* get_results(int num) {
    for (int i = 0; i < num; i++) {
        cres[i] = (res[i] == 1) ? 1 : 0;
    }
    return cres;
}

void free_gpu(int num) {
    GSV_verify_close(1);
    keccak_free();
    free(sig);
    free(res);    
}