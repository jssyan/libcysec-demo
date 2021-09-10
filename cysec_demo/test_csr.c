#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

static void test_csr_gen(void)
{
	const char* p[] = { "rsa", "sm2", "ecc" };
	int ret = 0;
	unsigned int n = 0;

	for(n = 0; n < sizeof(p)/sizeof(char*); n ++){
		PKEY_PCTX pctx = NULL;
		X509REQ_PCTX x509req = NULL;
		X509CRT_PCTX crt = NULL;
		char path[256] = {0};
		unsigned char *pem = NULL, *der = NULL;
		size_t plen = 0, dlen =0;

		snprintf(path, sizeof(path), "./kpool/%s.crt.pem", p[n]);
		crt = FILE_getcrt(path);
		s_assert((crt != NULL), "load certificate %s\n error", path);		

		if( strcmp(p[n], "rsa") == 0 ){
			pctx = cysec_pkey_gen_rsa(1024);
			s_assert((pctx != NULL), "failure to generate rsa \n");
		}else if( strcmp(p[n], "sm2") == 0 ){
			pctx = cysec_pkey_gen_sm2();
			s_assert((pctx != NULL), "failure to generate sm2 \n");
		}else if (strcmp(p[n], "ecc") == 0 ){
			pctx = cysec_pkey_gen_ecc(ECC_CURVE_SECP256R1);
			s_assert((pctx != NULL), "failure to generate ecc \n");
		}

		x509req = cysec_x509req_new(pctx);
		s_assert((x509req!=NULL),"generate x509req error...\n");

		ret = cysec_x509req_set_subject_name(x509req, cysec_x509crt_get_subject(crt));
		s_assert((ret==0),"x509req set subject name error...%08x\n",ret);

		ret = cysec_x509req_set_serialnumber(x509req, cysec_x509crt_get_sn(crt));
		s_assert((ret == 0), "x509req set serialnumber error...%08x\n",ret);

		ret = cysec_x509req_set_challengepw(x509req, "123456");
		s_assert((ret == 0),"x509req st challenge pw error...%08x\n",ret);

		ret = cysec_x509req_enable_skid(x509req);
		s_assert((ret == 0), "x509req enable skid error...%08x\n",ret);

		ret = cysec_x509req_set_altname(x509req,(const unsigned char *)"DQ5260C150107327",strlen("DQ5260C150107327"));
		s_assert((ret == 0), "set altname ,error = %08X\n", ret);

		ret = cysec_x509req_sign(x509req);
		s_assert((ret == 0), "x509req signature error...%08x\n",ret);

		ret = cysec_x509req_export(x509req, &pem, &plen, PEM);
		s_assert((ret == 0), "export x509req pem error ....%08x\n",ret);

		printf("the csr is (%s)\n",(char *)pem);


		ret = cysec_x509req_export(x509req, &der, &dlen, DER);
		s_assert((ret == 0), "export x509req der error ....%08x\n",ret);

		snprintf(path, sizeof(path),"./kpool/%s.csr.der",p[n]);
		FILE_putcontent(der, dlen, path);

		SAFE_FREE(pem);
		SAFE_FREE(der);
		cysec_pkey_free(pctx);
		cysec_x509crt_free(crt);
		cysec_x509req_free(x509req);
	}
}

int main(void)
{
	test_csr_gen();	
	exit(0);
}