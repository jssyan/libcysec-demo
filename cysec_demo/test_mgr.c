#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

static void test_certmgr_addcert(void) {
	CERTMGR_PCTX ctx;
	X509CRT_PCTX cacrt;
	X509CRT_PCTX crt;	
	
	const char* p[] = { "rsa", "ecc" ,"sm2"};
	char path[256];
	int n, ret;
	
	printf("certificate manager test...\n");
	for (n = 0; (unsigned int)n < sizeof(p)/sizeof(char *); n ++) {
		snprintf(path, sizeof(path), "%s/%s.n.rootcrt.pem", KPOOL_PATH, p[n]);
		cacrt = FILE_getcrt(path);
		if(!cacrt){
			printf("CA certificate not found.\n");
			break;
		}
		snprintf(path, sizeof(path), "%s/%s.n.crt.pem", KPOOL_PATH, p[n]);
		crt = FILE_getcrt(path);
		if(!crt){
			printf("certificate not found.\n");
			break;
		}

		ctx = certmgr_new();
		ret = certmgr_add_ca(ctx, cacrt);
		s_assert((ret == 0), "ret=%08x", ret);
		ret = certmgr_verify(ctx, crt);
		s_assert((ret == 0), "ret=%08x", ret);
		certmgr_free(ctx);
		
		x509crt_free(cacrt);
		x509crt_free(crt);
		printf("\n");
	}
}

static void test_certmgr_addpath(void) {
	CERTMGR_PCTX ctx;
	X509CRT_PCTX crt;	
	
	const char* p[] = { "rsa", "ecc" ,"sm2"};
	char path[256];
	int n, ret;
	
	printf("certificate manager test...\n");
	for (n = 0; (unsigned int)n < sizeof(p)/sizeof(char *); n ++) {
		snprintf(path, sizeof(path), "%s/%s.n.crt.pem", KPOOL_PATH, p[n]);
		crt = FILE_getcrt(path);
		if(!crt){
			printf("certificate not found.\n");
			break;
		}

		ctx = certmgr_new();
		ret = cysec_certmgr_add_capath(ctx, KPOOL_PATH);
		s_assert((ret == 0), "ret=%08x", ret);
		ret = certmgr_verify(ctx, crt);
		s_assert((ret == 0), "ret=%08x", ret);
		
		certmgr_free(ctx);
		x509crt_free(crt);
		printf("\n");
	}
}

int main(void )
{
	test_certmgr_addcert();
	test_certmgr_addpath();
	exit(0);
}