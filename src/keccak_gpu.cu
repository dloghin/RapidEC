// Based on cpu-tiny-sha3

// sha3.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

// Revised 07-Aug-15 to match with official release of FIPS PUB 202 "SHA3"
// Revised 03-Sep-15 for portability + OpenSSL - style API

#include <stdio.h>
#include <stdint.h>
#include "keccak_gpu.h"

#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

// state context
typedef struct
{
    union
    {                   // state:
        uint8_t b[200]; // 8-bit bytes
        uint64_t q[25]; // 64-bit words
    } st;
    int pt, rsiz, mdlen; // these don't overflow
} sha3_ctx_t;

// constants
const uint64_t host_keccakf_rndc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008};
const int host_keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
const int host_keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

__device__ __constant__ uint64_t gpu_keccakf_rndc[24];
__device__ __constant__ int gpu_keccakf_rotc[24];
__device__ __constant__ int gpu_keccakf_piln[24];

sha3_ctx_t *gpu_contexts;
char *gpu_in;
int *gpu_inlen;
int *gpu_offset;
char *gpu_md;

int *offsets;
char *out;

// update the state with given number of rounds

__device__ void sha3_keccakf(uint64_t st[25])
{
    // variables
    int i, j, r;
    uint64_t t, bc[5];

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    uint8_t *v;

    // endianess conversion. this is redundant on little-endian targets
    for (i = 0; i < 25; i++)
    {
        v = (uint8_t *)&st[i];
        st[i] = ((uint64_t)v[0]) | (((uint64_t)v[1]) << 8) |
                (((uint64_t)v[2]) << 16) | (((uint64_t)v[3]) << 24) |
                (((uint64_t)v[4]) << 32) | (((uint64_t)v[5]) << 40) |
                (((uint64_t)v[6]) << 48) | (((uint64_t)v[7]) << 56);
    }
#endif

    // actual iteration
    for (r = 0; r < KECCAKF_ROUNDS; r++)
    {

        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++)
        {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++)
        {
            j = gpu_keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, gpu_keccakf_rotc[i]);
            t = bc[0];
        }

        //  Chi
        for (j = 0; j < 25; j += 5)
        {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        //  Iota
        st[0] ^= gpu_keccakf_rndc[r];
    }

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    // endianess conversion. this is redundant on little-endian targets
    for (i = 0; i < 25; i++)
    {
        v = (uint8_t *)&st[i];
        t = st[i];
        v[0] = t & 0xFF;
        v[1] = (t >> 8) & 0xFF;
        v[2] = (t >> 16) & 0xFF;
        v[3] = (t >> 24) & 0xFF;
        v[4] = (t >> 32) & 0xFF;
        v[5] = (t >> 40) & 0xFF;
        v[6] = (t >> 48) & 0xFF;
        v[7] = (t >> 56) & 0xFF;
    }
#endif
}

// Initialize the context for SHA3

__device__ void sha3_init(sha3_ctx_t *c, int mdlen)
{
    int i;

    for (i = 0; i < 25; i++)
        c->st.q[i] = 0;
    c->mdlen = mdlen;
    c->rsiz = 200 - 2 * mdlen;
    c->pt = 0;
}

// update state with more data

__device__ void sha3_update(sha3_ctx_t *c, const void *data, size_t len)
{
    size_t i;
    int j;

    j = c->pt;
    for (i = 0; i < len; i++)
    {
        c->st.b[j++] ^= ((const uint8_t *)data)[i];
        if (j >= c->rsiz)
        {
            sha3_keccakf(c->st.q);
            j = 0;
        }
    }
    c->pt = j;
}

// finalize and output a hash
__device__ void sha3_final(void *md, sha3_ctx_t *c)
{
    int i;

    c->st.b[c->pt] ^= 0x06;
    c->st.b[c->rsiz - 1] ^= 0x80;
    sha3_keccakf(c->st.q);

    for (i = 0; i < c->mdlen; i++)
    {
        ((uint8_t *)md)[i] = c->st.b[i];
    }
}

// compute a SHA-3 hash (md) of given byte length from "in"

__global__ void sha3(int num, sha3_ctx_t *contexts, const void *in, int *inlen, int *offset, void *md, int mdlen)
{
    int const tid = threadIdx.x;

    sha3_init(contexts + tid, mdlen);
    sha3_update(contexts + tid, in + offset[tid], inlen[tid]);
    sha3_final(md + (tid * mdlen), contexts + tid);
}

__host__ int keccak_init(int num)
{
    cudaError_t ret;
    ret = cudaMemcpyToSymbol(gpu_keccakf_rndc, host_keccakf_rndc, 24 * sizeof(uint64_t));
    ret = cudaMemcpyToSymbol(gpu_keccakf_rotc, host_keccakf_rotc, 24 * sizeof(int));
    ret = cudaMemcpyToSymbol(gpu_keccakf_piln, host_keccakf_piln, 24 * sizeof(int));

    ret = cudaMalloc(&gpu_contexts, num * sizeof(sha3_ctx_t));
    if (ret != cudaSuccess)
    {
        printf("Error in allocating contexts!\n");
        return 1;
    }

    ret = cudaMalloc(&gpu_in, num * 1024);
    if (ret != cudaSuccess)
    {
        printf("Error in allocating input!\n");
        return 1;
    }

    ret = cudaMalloc(&gpu_inlen, num * sizeof(int));
    if (ret != cudaSuccess)
    {
        printf("Error in allocating inlen!\n");
        return 1;
    }

    ret = cudaMalloc(&gpu_offset, num * sizeof(int));
    if (ret != cudaSuccess)
    {
        printf("Error in allocating offset!\n");
        return 1;
    }

    ret = cudaMalloc(&gpu_md, num * 32);
    if (ret != cudaSuccess)
    {
        printf("Error in allocating md output!\n");
        return 1;
    }

    offsets = (int *)malloc(num * sizeof(int));
    if (!offsets)
    {
        printf("Error in allocating CPU offsets!\n");
        return 1;
    }

    out = (char *)malloc(num * 32);
    if (!offsets)
    {
        printf("Error in allocating CPU output!\n");
        return 1;
    }

    return 0;
}

int keccak_kernel(unsigned char *data, int *sizes, int num)
{
    cudaError_t ret;

    int sum = sizes[0];
    offsets[0] = 0;
    for (int i = 1; i < num; i++)
    {
        offsets[i] = sum;
        sum += sizes[i];
    }

    ret = cudaMemcpy(gpu_in, data, sum, cudaMemcpyHostToDevice);
    if (ret != cudaSuccess)
    {
        printf("Error in copy input!\n");
        return 1;
    }

    ret = cudaMemcpy(gpu_inlen, sizes, num * sizeof(int), cudaMemcpyHostToDevice);
    if (ret != cudaSuccess)
    {
        printf("Error in copy inlen!\n");
        return 1;
    }

    ret = cudaMemcpy(gpu_offset, offsets, num * sizeof(int), cudaMemcpyHostToDevice);
    if (ret != cudaSuccess)
    {
        printf("Error in copy offsets!\n");
        return 1;
    }

    sha3<<<1, num>>>(num, gpu_contexts, gpu_in, gpu_inlen, gpu_offset, gpu_md, 32);

    return 0;
}

unsigned char *keccak_get_results(int num)
{
    cudaError_t ret;

    ret = cudaMemcpy(out, gpu_md, num * 32, cudaMemcpyDeviceToHost);
    if (ret != cudaSuccess)
    {
        printf("Error in copy output!\n");
        return NULL;
    }
    return (unsigned char *)out;
}

void keccak_free()
{
    cudaFree(gpu_contexts);
    cudaFree(gpu_in);
    cudaFree(gpu_inlen);
    cudaFree(gpu_offset);
    cudaFree(gpu_md);
    free(offsets);
    free(out);
}
