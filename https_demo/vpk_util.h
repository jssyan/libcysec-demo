#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <cysec.h>


#if !defined(s_assert)
#define s_assert(v, fmt, arg...) \
	do { \
		if (!(v)) { \
			printf("[ASSERT] %s:%d " fmt "\n", __FILE__, __LINE__, ##arg); \
		} \
} while(0)
#endif

#define KPOOL_PATH "./kpool"

struct benchmark_st {
	int loop;
	int round;
	double s;
	double e;
};

struct benchmark_st _bm;

unsigned char* FILE_getcontent(const char* fname, size_t* len);
int FILE_putcontent(const unsigned char *in, size_t ilen, const char *fname);
void fillbuf(unsigned char* buf, size_t blen);
X509CRT_PCTX FILE_getcrt(const char* fname);
PKEY_PCTX FILE_getpvk(const char* fname);
double benchmark_current_time(void);
void onalarm(int sig);
void benchmark(int reset);

/* 调用cysec接口模拟芯片或者密码卡生成私钥句柄 */
PKEY_PCTX test_pkey_custom_load(const char *path);
/* 调用cysec接口模拟芯片或者密码卡生成ECC私钥句柄 */
PKEY_PCTX test_pkey_custom_gen_ecc(const char *path);
/* 调用cysec接口模拟芯片或者密码卡生成RSA私钥句柄 */
PKEY_PCTX test_pkey_custom_gen_rsa(const char *path);
/* 调用cysec接口模拟芯片或者密码卡生成SM2私钥句柄 */
PKEY_PCTX test_pkey_custom_gen_sm2(const char *path);
