#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <cysec.h>
#include <signal.h>
#include "vpk_util.h"

#if !defined(SAFE_FREE)
#define SAFE_FREE(x) do{ if(x) free(x); x=NULL; }while(0)
#endif

#if !defined(s_assert)
#define s_assert(v, fmt, arg...) \
	do { \
		if (!(v)) { \
			printf("[ASSERT] %s:%d " fmt "\n", __FILE__, __LINE__, ##arg); \
		} \
} while(0)
#endif

#define KPOOL_PATH "./kpool"

unsigned char* FILE_getcontent(const char* fname, size_t* len) {
  FILE *fp = NULL;
  unsigned char* r = NULL;
  long l;
  
  if ((fp = fopen(fname,"r"))==NULL) {
    return NULL;
  }
  fseek(fp, 0, SEEK_END);
  l = ftell(fp);
  if (l > 0) {
    r = (unsigned char *)malloc(l + 1);
    fseek(fp, 0, SEEK_SET);
    if (fread(r, l, 1, fp) <= 0) {
			free(r);
			r = NULL;
			l = 0;
			goto end;
		}
		r[l] = '\0';
  }
	
end:
	if (len != NULL) {
  	*len = l ;
	}
  fclose(fp);
  return r;
}

int FILE_putcontent(const unsigned char *in, size_t ilen, const char *fname){
	FILE *fp = NULL;
	int ret = 0;

	if ((fp = fopen(fname,"w"))==NULL) {
		return -1;
  	} 

  	if(in && ilen > 0){
  		ret = fwrite(in, 1, ilen, fp);
  		if(ret != ilen){
  			fclose(fp);
  			return -1;
  		}
  	}

  	fclose(fp);
  	return 0;
}

void fillbuf(unsigned char* buf, size_t blen) {
	size_t n;
	for (n = 0; n < blen; n ++) {
		buf[n] = (n & 0xff);
	}
}

static void dumpcrt(X509CRT_PCTX x) {
  if (!x) {
    printf("crt is NULL! xxxxxxxxxxxxxxxxxxxx \n");
    return;
  }
  printf("+++++ subject=[%s] issuer=[%s] sn=[%s] notbefore=[%s] notafter=[%s]\n", 
      x509crt_get_subject(x),
      x509crt_get_issuer(x),
      x509crt_get_sn(x),
      x509crt_get_notbefore(x),
      x509crt_get_notafter(x));
}


static void dumpkey(PKEY_PCTX x) {
	if (!x) {
		printf("key is NULL! xxxxxxxxxxxxxxxxxxxx \n");
		return;
	}
	printf("----- keytype=[%s] bits=[%d] private=[%d]\n", 
		pkey_is_rsa(x) ? "rsa" : (pkey_is_sm2(x) ? "sm2" : (pkey_is_ecc(x) ? "ecc" : "unknown")),
		pkey_get_bits(x),
		pkey_is_private(x));
}

X509CRT_PCTX FILE_getcrt(const char* fname) {
	unsigned char* buf = NULL;
	size_t len;
	X509CRT_PCTX r = NULL;

	printf("loading certificate from file (%s)....\n", fname);
	buf = FILE_getcontent(fname, &len);
	if (buf) {
		r = x509crt_load(buf, len);
		dumpcrt(r);
	}
	SAFE_FREE(buf);
	return r;
}

PKEY_PCTX FILE_getpvk(const char* fname) {
	unsigned char* buf = NULL;
	size_t len;
	PKEY_PCTX r = NULL;

	printf("loading private key from file (%s)....\n", fname);
	buf = FILE_getcontent(fname, &len);
	if (buf) {
		r = pkey_load_private(buf, len, NULL);
		dumpkey(r);
	}
	SAFE_FREE(buf);
	return r;
}

double benchmark_current_time(void) {
  struct timeval tv;
  gettimeofday(&tv, 0);

  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

void onalarm(int sig) {
	signal(SIGALRM, SIG_IGN);
	_bm.loop = 0;
}

void benchmark(int reset) {
	if (reset) {
		_bm.round = 0;
		_bm.loop = 1;
		signal(SIGALRM, onalarm);
		alarm(3);
		_bm.s = benchmark_current_time();
	}
	else {
		_bm.e = benchmark_current_time() - _bm.s;
	}
}


#ifdef HAVE_PK_CUSTOM_SUPPORT
struct user_pk_context
{
	 PKEY_PCTX key;
};

static void *test_user_pk_context_alloc()
{
	struct user_pk_context *r = NULL;

	r = calloc(1, sizeof(struct user_pk_context));
	
	return (void *)r;
}

static void test_user_pk_context_free(void *ctx)
{
	struct user_pk_context *r = (struct user_pk_context *)ctx;

	if(r){
		if(r->key)
			cysec_pkey_free(r->key);
		free(r);
	}
}

static size_t test_user_pk_context_get_bitlen(const void *ctx)
{
	struct user_pk_context *r = (struct user_pk_context *)ctx;

	if(r && r->key)
		return cysec_pkey_get_bits(r->key);
	return 0;
}

static int test_pkey_custom_sign_func(void *ctx, HASH_ALG hash_alg, const unsigned char *hash, size_t hash_len,
				unsigned char *sig, size_t *sig_len)
{
	struct user_pk_context *r = (struct user_pk_context *)ctx;

	if(!r)
		return -1;

	return cysec_pkey_digest_sign(r->key, hash, hash_len, hash_alg, sig, sig_len);
}


static int test_pkey_custom_decrypt_func(void *ctx, const unsigned char *input, size_t ilen,
				unsigned char *output, size_t *olen, size_t osize)
{
	struct user_pk_context *r = (struct user_pk_context *)ctx;

	if(!r)
		return -1;

	*olen = osize;
	return cysec_pkey_private_decrypt(r->key, input, ilen, output, olen);
}


static int test_user_pk_context_copy(void *dst, const void *src)
{
	struct user_pk_context *s = (struct user_pk_context *)src;
	struct user_pk_context *d = (struct user_pk_context *)dst;
	int ret = 0;

	if(!dst || !src)
		return -1;

	if(d->key == NULL){
		if(cysec_pkey_is_rsa(s->key) == 1)
			d->key = cysec_pkey_gen_rsa(cysec_pkey_get_bits(s->key));
		else if (cysec_pkey_is_ecc(s->key) == 1)
			d->key = cysec_pkey_gen_ecc_by_name(cysec_pkey_ecc_get_curve_name(s->key));
		else
			d->key = cysec_pkey_gen_sm2();

		if(!d->key)
			return -1;
	}
	return cysec_pkey_copy(d->key, s->key);
}


PKEY_PCTX test_pkey_custom_gen_rsa(const char *path)
{
	unsigned char n[512] = {0};
	unsigned char e[512] = {0};
	int ret;
	PKEY_PCTX tmp, r = NULL;
	size_t nlen = sizeof(n), elen = sizeof(e);
	struct user_pk_context *user_context;

	tmp = FILE_getpvk(path);
	if(!tmp)
		return NULL;

	if(cysec_pkey_is_rsa(tmp)!=1){
		cysec_pkey_free(tmp);
		return NULL;
	}

	ret = cysec_pkey_rsa_get_public_elements(tmp, n, &nlen, e, &elen);
	if(ret){
		cysec_pkey_free(tmp);
		return NULL;
	}

	cysec_pkey_free(tmp);
	r = cysec_pkey_load_private_custom_rsa(n, nlen, e, elen, test_user_pk_context_alloc,
		test_user_pk_context_free, test_user_pk_context_copy);
	if(!r) {
		cysec_pkey_free(tmp);
		return NULL;
	}

	user_context = cysec_pkey_custom_get0_user_ctx(r);
	if(!user_context){
		cysec_pkey_free(r);
		return NULL;
	}

	user_context->key = FILE_getpvk(path);
	if(!user_context->key) {
		cysec_pkey_free(r);
		return NULL;
	}

	ret = cysec_pkey_custom_set_sign_func(r, test_pkey_custom_sign_func );
	if(ret){
		cysec_pkey_free(r);
		return NULL;
	}

	ret = cysec_pkey_custom_set_decrypt_func(r, test_pkey_custom_decrypt_func);
	if(ret){
		cysec_pkey_free(r);
		return NULL;
	}

	return r;
}

PKEY_PCTX test_pkey_custom_gen_ecc(const char *path)
{
	unsigned char x[64] = {0};
	unsigned char y[64] = {0};
	int ret;
	PKEY_PCTX tmp, r = NULL;
	size_t xlen = sizeof(x), ylen = sizeof(y);
	struct user_pk_context *user_context;
	PKEY_ECC_CURVE cid = ECC_CURVE_NONE;

	tmp = FILE_getpvk(path);
	if(!tmp)
		return NULL;

	if(cysec_pkey_is_ecc(tmp)!=1){
		cysec_pkey_free(tmp);
		return NULL;
	}

	ret = cysec_pkey_ecc_get_public_elements(tmp, &cid, x, &xlen, y, &ylen);
	if(ret){
		cysec_pkey_free(tmp);
		return NULL;
	}

	cysec_pkey_free(tmp);
	r = cysec_pkey_load_private_custom_ecc(cid, x, xlen, y, ylen, test_user_pk_context_alloc,
		test_user_pk_context_free, test_user_pk_context_copy);
	if(!r) {
		cysec_pkey_free(tmp);
		return NULL;
	}

	user_context = cysec_pkey_custom_get0_user_ctx(r);
	if(!user_context){
		cysec_pkey_free(r);
		return NULL;
	}

	user_context->key = FILE_getpvk(path);
	if(!user_context->key) {
		cysec_pkey_free(r);
		return NULL;
	}

	ret = cysec_pkey_custom_set_sign_func(r, test_pkey_custom_sign_func);
	if(ret){
		cysec_pkey_free(r);
		return NULL;
	}

	ret = cysec_pkey_custom_set_decrypt_func(r, test_pkey_custom_decrypt_func);
	if(ret){
		cysec_pkey_free(r);
		return NULL;
	}

	return r;
}

PKEY_PCTX test_pkey_custom_gen_sm2(const char *path)
{
	return test_pkey_custom_gen_ecc(path);
}

PKEY_PCTX test_pkey_custom_load_rsa(const char *path)
{
	return test_pkey_custom_gen_rsa(path);
}

PKEY_PCTX test_pkey_custom_load_sm2(const char *path)
{
	return test_pkey_custom_gen_sm2(path);
}

PKEY_PCTX test_pkey_custom_load_ecc(const char *path)
{
	return test_pkey_custom_gen_ecc(path);
}

PKEY_PCTX test_pkey_custom_load(const char *path)
{
	PKEY_PCTX tmp = NULL, r = NULL;

	tmp = FILE_getpvk(path);
	if(!tmp)
		return NULL;

	if( cysec_pkey_is_rsa(tmp) == 1) {
		r = test_pkey_custom_load_rsa(path);
	} else if (cysec_pkey_is_sm2(tmp) == 1) {
		r = test_pkey_custom_load_sm2(path);
	} else if (cysec_pkey_is_ecc(tmp) == 1) {
		r = test_pkey_custom_load_ecc(path);
	}

	cysec_pkey_free(tmp);
	return r;
}

#endif
