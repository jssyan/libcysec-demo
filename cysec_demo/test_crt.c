#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

static void test_load_bmp_cert(void)
{
	char path[256] = {0};
	int n, ret;
	X509CRT_PCTX crt;	

	snprintf(path, sizeof(path), "%s/bmp.crt.pem", KPOOL_PATH);
	crt = FILE_getcrt(path);
	if(!crt){
		printf("certificate not found.\n");
		return;
	}

	cysec_x509crt_free(crt);
	return;
}

void main()
{
	test_load_bmp_cert();
}