#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

static void test_hmac(void) {
	int halgs[] = { HASH_ALG_SHA384, HASH_ALG_SHA256, HASH_ALG_SM3 };
	const char* salgs[] = { "sha384", "sha256", "sm3" };
	int sizes[] = { 16, 64, 256, 1024, 4096 };
	HMAC_PCTX h;
	int n, m;
	unsigned char in[4096];
	unsigned char out[64];
	const char key[16];

	for (n = 0; (unsigned int)n < sizeof(halgs)/sizeof(int); n ++) {
		for (m = 0; (unsigned int)m < sizeof(sizes)/sizeof(int); m ++) {
			printf("hmac(%d) name=[%s] buffersize=[%d] ", halgs[n], salgs[n], sizes[m]);
			benchmark(1);
			while (_bm.loop) {
				h = hmac_ctx_new(halgs[n]);
				hmac_init(h, (const unsigned char *)key, sizeof(key));
				hmac_update(h, in, sizes[m]);
				hmac_final(h, out);
				hmac_ctx_free(h);
				_bm.round ++;
			}
			benchmark(0);
			printf("round=[%d] time=[%fs] throughput=[%.2f]MB/s\n", _bm.round, _bm.e, _bm.round*sizes[m]/(_bm.e * 1000000));
		}
	}
}

int main(void) {
	test_hmac();
	return 0;
}
