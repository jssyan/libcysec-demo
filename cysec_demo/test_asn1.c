#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

#ifndef CYSEC_NO_ASN1
static void test_asn1(void)
{
	char path[256] = {0};
	unsigned char *file_content = NULL;
	size_t file_sz = 0;
	unsigned int inOutIdx = 0, fileIdx = 0, p7Idx = 0;
	int ret = 0;
	int length = 0, orig_file_length = 0, p7len = 0;
	HASH_ALG alg = HASH_ALG_SHA256;
	DIGEST_PCTX dctx = NULL;
	unsigned char digest[128] = {0};
	int dgst_sz = 0;
	X509CRT_PCTX x509 = NULL;
	X509CRT_PCTX cacert = NULL;
	CERTMGR_PCTX cm = NULL;
	int version = 0;

	snprintf(path, sizeof(path),"./kpool/sm2.application.bin");
	file_content = FILE_getcontent(path, &file_sz);
	s_assert((file_content!=NULL),"Failure to load %s\n", path);

	ret = cysec_asn1_get_sequence(file_content, &inOutIdx, &length, file_sz);
	s_assert((ret == 0), "Failure to parse sequence ,error = %08X \n",ret);

	ret = cysec_asn1_get_version(file_content, &inOutIdx, &version, file_sz);
	s_assert((ret == 0), "Failure get version, error = %08X \n",ret);

	s_assert((version == 1),"the version is %d\n", version);

#if 0
	ret = cysec_asn1_get_octstring(file_content, &inOutIdx, &orig_file_length, file_sz);
	s_assert((ret == 0), "Failure to parse application content, error = %08x\n", ret);

	fileIdx = inOutIdx;
	inOutIdx += orig_file_length;
#endif

	ret = cysec_asn1_get_hashalg(file_content, &inOutIdx, file_sz, &alg);
	s_assert((ret == 0), "Failure to parse hash alg ,error = %08x\n", ret);

	ret = cysec_asn1_get_octstring(file_content, &inOutIdx, &p7len, file_sz);
	s_assert((ret == 0), "Failure to parse pkcs7 ,error = %08x\n", ret);	

	p7Idx = inOutIdx;
	inOutIdx += p7len;

#if 1
	ret = cysec_asn1_get_octstring(file_content, &inOutIdx, &orig_file_length, file_sz);
	s_assert((ret == 0), "Failure to parse application content, error = %08x\n", ret);

	fileIdx = inOutIdx;
	inOutIdx += orig_file_length;
#endif

	dctx = cysec_digest_ctx_new(alg);
	s_assert((digest!=NULL),"Failure to new a digest ctx\n");

	dgst_sz = cysec_digest_size(alg);
	s_assert((dgst_sz<128 && dgst_sz >0), "dgst_sz is error,%d\n", dgst_sz);

	ret =cysec_digest_init(dctx, NULL);
	s_assert((ret == 0),"digest init ,error = %08x\n", ret);

	while(orig_file_length){
		if(orig_file_length >= 1024){
			ret = cysec_digest_update(dctx, file_content + fileIdx, 1024);
			s_assert((ret == 0),"digest Update . error= %08x\n", ret);
			fileIdx += 1024;
			orig_file_length -= 1024;
		}else{
			ret = cysec_digest_update(dctx, file_content + fileIdx, orig_file_length);
			s_assert((ret == 0),"digest Update . error= %08x\n", ret);
			fileIdx += orig_file_length;
			orig_file_length -= orig_file_length;		
		}
	}

	ret =  cysec_digest_final(dctx,digest);
	s_assert((ret ==0), "digest final, error = %08x\n",ret);

	#if 1
	int j = 0; for(j=0; j<dgst_sz; j++) printf("%02X",digest[j]);
	#endif
	ret = cysec_pkcs7_detached_verify(digest, dgst_sz, file_content+p7Idx, p7len, &x509 );
	s_assert((ret == 0), "Verify failure , error = %08X\n",ret);

	if(x509){
		snprintf(path, sizeof(path), "./kpool/sm2.scep.rootcrt.pem");
		cacert = FILE_getcrt(path);
		s_assert((cacert!=NULL),"failed to load ca certificate\n");

		cm = cysec_certmgr_new();
		s_assert((cm!=NULL),"failed to new certmgr\n");

		ret = cysec_certmgr_add_ca(cm, cacert);
		s_assert((ret==0), "failed to add cacert ,error = %08X\n",ret);

		ret = cysec_certmgr_verify(cm,x509);
		s_assert((ret == 0), "verify certificate failure, error = %08X\n",ret);
	}

	if(x509)
		cysec_x509crt_free(x509);
	if(cacert)
		cysec_x509crt_free(cacert);
	if(cm)
		cysec_certmgr_free(cm);
	if(file_content)
		SAFE_FREE(file_content);
	if(dctx)
		cysec_digest_ctx_free(dctx);

}

int main(void)
{
	test_asn1();
	return 0;
}
#else
void main(void)
{
}

#endif // CYSEC_NO_ASN1
