#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

#ifndef CYSEC_NO_PKCS5

void test_pbes()
{
	PBES2_PCTX ctx = NULL;
	const char *message="It's a message.";
	int ret = 0 ;
	unsigned char *out = NULL, *plain = NULL;
	size_t olen = 0, plen = 0;

	ctx = cysec_pbes2_new();
	if(!ctx) {
		printf("out of memory.\n");
		goto err;
	}

	ret = cysec_pbes2_encrypt_init(ctx, CIPHER_ALG_SM4_CBC, HASH_ALG_SM3, 10000, 1);
	if(ret){
		printf("init pbes2 failed. error(%08x\n)",ret);
		goto err;
	}

	ret = cysec_pbes2_encrypt(ctx, (const unsigned char *)message, strlen(message), (const unsigned char *)"passwd", strlen("passwd"),
		&out, &olen);
	if(ret) {
		printf("encrypt pbes2 failed. error(%08x\n)",ret);
		goto err;	
	}

	ret = FILE_putcontent(out, olen, "pbes_encrypt.der");
	if(ret){
		printf("write to pbes_encrypt.der failed.\n");
		goto err;
	}

	ret =cysec_pbes2_decrypt(out, olen, (const unsigned char *)"passwd", strlen("passwd"),
		&plain, &plen);
	if(ret) {
		printf("decrypt pbes2 failed, error(%08x\n)", ret);
		goto err;
	}

	if( plen != strlen(message) || memcmp(plain, message, plen) != 0){
		printf("test failed.\n");
		goto err;
	} else
		printf("test success.\n");

err:
	if(ctx)
		cysec_pbes2_free(ctx);
	if(out)
		free(out);
	if(plain)
		free(plain);

	return;
}

int main()
{
	test_pbes();
}
#else
void main()
{

}
#endif
