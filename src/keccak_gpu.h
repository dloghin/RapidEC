
int keccak_init(int num);

int keccak_kernel(unsigned char* data, int* sizes, int num);

unsigned char* keccak_get_results(int num);

void keccak_free();