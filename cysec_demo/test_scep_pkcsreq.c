#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

#if !(CYSEC_NO_SCEP) && !(CYSEC_NO_TLS)
static char* bin2hex(const unsigned char *old, const size_t oldlen)
{
    char *result = (char*) malloc(oldlen * 2 + 1);
    size_t i, j;
    int b = 0;

    for (i = j = 0; i < oldlen; i++) {
        b = old[i] >> 4;
        result[j++] = (char) (87 + b + (((b - 10) >> 31) & -39));
        b = old[i] & 0xf;
        result[j++] = (char) (87 + b + (((b - 10) >> 31) & -39));
    }
    result[j] = '\0';
    return result;

}

static void test_scep_request(int unenveloped)
{
	const char* p[] = { "rsa", "sm2" };
	int ret = 0;
	unsigned int n = 0;

	for(n = 0; (unsigned int)n < sizeof(p)/sizeof(char*); n ++){
		PKEY_PCTX local_pctx = NULL;
		X509REQ_PCTX x509req = NULL;
		X509CRT_PCTX selfcrt = NULL;
		X509CRT_PCTX scepsvr_crt = NULL;
		char path[256] = {0};
		unsigned char *req_pem = NULL, *req_der = NULL, *privatekey_pem = NULL;
		size_t plen = 0, rlen = 0, prikeypemlen = 0;
		SCEP_REQUEST_PCTX req = NULL;	
		const char *sn= "CN=7310500000000X_VIN_LSGBL5334HF000020,OU=China,O=SGM";
		DIGEST_PCTX dctx = NULL;
		unsigned char digest[128] = {0};
		char *digest_hex = NULL;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.scep.scepsvr.pem", p[n]);
		scepsvr_crt = FILE_getcrt(path);
		s_assert((scepsvr_crt != NULL), "load certificate %s\n error", path);
		if(!scepsvr_crt){
			printf("Load certificate %s\n error",path);
			break;
		}	

		if( strcmp(p[n], "rsa") == 0 ){
			local_pctx = cysec_pkey_gen_rsa(1024);
			s_assert((local_pctx != NULL), "failure to generate rsa \n");
		}else if( strcmp(p[n], "sm2") == 0 ){
			local_pctx = cysec_pkey_gen_sm2();
			s_assert((local_pctx != NULL), "failure to generate sm2 \n");
		}

		if(!local_pctx)
			goto freebuffer;

		ret = cysec_pkey_export_privatekey(local_pctx, &privatekey_pem, &prikeypemlen, PEM);
		s_assert((ret == 0), "export private key error(%08X).\n", ret);
		if(ret)
			goto freebuffer;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.scep.pvk.pem", p[n]);		
		ret = FILE_putcontent(privatekey_pem, prikeypemlen, path);
		SAFE_FREE(privatekey_pem);

		x509req = cysec_x509req_new(local_pctx);
		s_assert((x509req!=NULL),"generate x509req error...\n");	
		if(!x509req)
			goto freebuffer;

		/*
		ret = cysec_x509req_set_subject_name(x509req, cysec_x509crt_get_subject(crt));
		s_assert((ret==0),"x509req set subject name error...%08x\n",ret);
		*/
		ret = cysec_x509req_set_subject_name(x509req, sn);
		s_assert((ret==0),"x509req set subject name error ...%08X\n",ret);
		if(ret)
			goto freebuffer;

		ret = cysec_x509req_set_serialnumber(x509req,"00:01:02:03");
		s_assert((ret == 0), "x509req set serialnumber error...%08x\n",ret);
		if(ret)
			goto freebuffer;

		dctx = cysec_digest_ctx_new(HASH_ALG_SHA256);
		s_assert((dctx!=NULL),"digest new error");
		if(!dctx)
			goto freebuffer;

		ret = cysec_digest_init(dctx, NULL);
		s_assert((ret == 0), "digest init ,error = %08X\n",ret);
		if(ret)
			goto freebuffer;

		ret = cysec_digest_update(dctx,(const unsigned char *)"DQ5260C150107327",
			strlen("DQ5260C150107327"));
		s_assert((ret == 0), "digest update, error = %08x\n", ret);
		if(ret)
			goto freebuffer;

		ret = cysec_digest_final(dctx, digest);
		s_assert((ret == 0), "digest final, error = %08x\n", ret);
		if(ret)
			goto freebuffer;

		digest_hex = bin2hex(digest, 32);
		//ret = cysec_x509req_set_altname(x509req, digest_hex, strlen(digest_hex));
		int j=0; for(j=0; j<32; j++) printf("%02X", digest[j]); printf("\n");
		ret = cysec_x509req_set_altname(x509req, digest, 32);
		//ret = cysec_x509req_set_altname(x509req,"DQ5260C150107327",strlen("DQ5260C150107327"));
		s_assert((ret == 0), "set altname ,error = %08X\n", ret);
		if(ret)
			goto freebuffer;

		ret = cysec_x509req_set_challengepw(x509req, "password");
		s_assert((ret == 0),"x509req st challenge pw error...%08x\n",ret);
		if(ret)
			goto freebuffer;

		ret = cysec_x509req_enable_skid(x509req);
		s_assert((ret == 0), "x509req enable skid error...%08x\n",ret);
		if(ret)
			goto freebuffer;

		ret = cysec_x509req_sign(x509req);
		s_assert((ret == 0), "x509req signature error...%08x\n",ret);
		if(ret)
			goto freebuffer;

		ret = cysec_x509req_export(x509req, &req_pem, &plen, PEM);
		s_assert((ret == 0), "export x509req pem error ....%08x\n",ret);
		if(ret)
			goto freebuffer;
		printf("the (%s) csr is (%s)\n",p[n],(char *)req_pem);

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.scep.req.pem", p[n]);		
		ret = FILE_putcontent(req_pem, plen, path);
		/** scep */
		selfcrt =cysec_x509req_to_x509(x509req);
		s_assert((selfcrt!=NULL),"generate selfcert error .\n");
		if(!selfcrt)
			goto freebuffer;

		snprintf(path, sizeof(path), "./kpool/%s.scep.selfsign.crt.pem", p[n]);		
		ret = FILE_putcontent((const unsigned char *)cysec_x509crt_as_pem(selfcrt), strlen(cysec_x509crt_as_pem(selfcrt)), path);
		if(ret)
			goto freebuffer;

		req = cysec_scep_request_pkcsreq_new(x509req, selfcrt, local_pctx, unenveloped ? NULL: scepsvr_crt);
		s_assert((req!=NULL),"generate the scep request(pkcsreq) error ..\n");
		if(!req)
			goto freebuffer;

		ret = cysec_scep_request_encode(req, &req_der, &rlen);
		s_assert((ret == 0), "scep encode error ..ret(%08X)\n",ret);
		if(ret)
			goto freebuffer;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), unenveloped? "./kpool/%s.scep.pkcsreq_unenveloped.der": "./kpool/%s.scep.pkcsreq.der", p[n]);		
		ret = FILE_putcontent(req_der,rlen, path);

		printf("generate and write pkcsreq(%s) success.\n",p[n]);
freebuffer:
		SAFE_FREE(req_der);
		SAFE_FREE(req_pem);
		SAFE_FREE(privatekey_pem);
		SAFE_FREE(digest_hex);
		if(req)
			cysec_scep_request_free(req);
		SAFE_FREE(req_pem);
		if(local_pctx)
			cysec_pkey_free(local_pctx);
		if(selfcrt)
			cysec_x509crt_free(selfcrt);
		if(scepsvr_crt)
			cysec_x509crt_free(scepsvr_crt);
 		if(x509req)
			cysec_x509req_free(x509req);
		if(dctx)
			cysec_digest_ctx_free(dctx);
	}
}

/** for testing purpose. */
static int scep_verifysigner_cb(X509CRT_PCTX signer, void *userdata)
{
	CERTMGR_PCTX cm = (CERTMGR_PCTX)userdata;	
	int ret = 0;

	if(!signer || !userdata)
		return 0;
	
	ret = cysec_certmgr_verify(cm, signer);
	s_assert((ret == 0), "Verify Certificate Chain Failure, ret = %08x\n", ret);
	
	return (ret == 0) ? 1 : 0;
}

static void test_scep_respond(int unenveloped)
{
	const char* p[] = { "rsa", "sm2"};
	int ret = 0;
	unsigned int n = 0;

	for(n = 0; (unsigned int )n < sizeof(p)/sizeof(char*); n ++){
		PKEY_PCTX local_pctx = NULL;
		X509CRT_PCTX local_crt = NULL;
		char path[256] = {0};
		unsigned char *pem = NULL;
		SCEP_RESPONSE_PCTX rsp = NULL;
		unsigned char *rsp_der = NULL;
		size_t rsp_dlen = 0;
		X509CRT_PCTX issuedcert = NULL, issued_enccert = NULL;
		PKEY_PCTX enc_pvk = NULL;
		unsigned char *enc_pvk_buf = NULL;
		size_t enc_pvk_buf_len = 0;
		CERTMGR_PCTX cm = NULL;
		X509CRT_PCTX cacert= NULL;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.scep.ca.crt.pem", p[n]);
		cacert = FILE_getcrt(path);
		s_assert((cacert != NULL), "load scep server certificate %s\n error", path);
		if(!cacert)
			goto freebuffer;	

		snprintf(path, sizeof(path), "./kpool/%s.scep.selfsign.crt.pem", p[n]);
		local_crt = FILE_getcrt(path);
		s_assert((local_crt != NULL), "load local certificate %s\n error", path);
		if(!local_crt)
			goto freebuffer;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.scep.pvk.pem", p[n]);
		local_pctx = FILE_getpvk(path);
		s_assert((local_pctx != NULL), "load local prviatekey %s\n error", path);
		if(!local_pctx)
			goto freebuffer;	

		cm = certmgr_new();
		if(!cm)
			goto freebuffer;

		if(cacert)
			ret = certmgr_add_ca(cm, cacert);
		s_assert((ret == 0), "ret=%d\n", ret);
		if(ret)
			goto freebuffer;

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), unenveloped ? "./kpool/%s.scep.certrep_unenveloped.der":"./kpool/%s.scep.certrep.der", p[n]);		
		rsp_der = FILE_getcontent(path, &rsp_dlen);
		if(!rsp_der)
			goto freebuffer;

		rsp = cysec_scep_response_certrep_new(local_crt,  unenveloped? NULL:local_pctx);
		s_assert("rsp!=NULL", "generate the scep response error ..\n");
		if(!rsp)
			goto freebuffer;

		ret = cysec_scep_response_set_verifysigner_callback(rsp, scep_verifysigner_cb, (void *)cm);
		s_assert((ret == 0), "set verifysigner error \n");
		if(ret)
			goto freebuffer;

		ret = cysec_scep_response_decode(rsp_der, rsp_dlen, rsp);
		s_assert((ret == 0), "decode scep message error (%08X)", ret);
		if(ret)
			goto freebuffer;

		ret = cysec_scep_response_get_messagetype(rsp);
		s_assert((ret == 3), "the messagetype(%d) is not expected",ret);

		ret = cysec_scep_response_get_pkistatus(rsp);
		s_assert((ret == 0), "the pkistatus is (%d)\n", ret);
		if(ret != 0) {
			ret = cysec_scep_response_get_failinfo(rsp);
			printf("the failinfo is %d\n", ret);
			goto freebuffer;
		}

		issuedcert = cysec_scep_response_certrep_get_issuedcert(rsp);
		s_assert((issuedcert!=NULL),"fail to get issued certificate\n");

		if(issuedcert){
			printf("===================GetCert===========================\n");
			dumpcrt(issuedcert);
			printf("===================success===========================\n");
		}

		memset(path, 0, sizeof(path));
		snprintf(path, sizeof(path), "./kpool/%s.scep.crt.pem", p[n]);
		ret = FILE_putcontent((const unsigned char *)cysec_x509crt_as_pem(issuedcert), strlen(cysec_x509crt_as_pem(issuedcert)), path);
		if(ret)
			goto freebuffer;		

#ifndef CYSEC_NO_CNCAV1_1
		issued_enccert = cysec_scep_response_certrep_get_issued_enccert(rsp);
		if(issued_enccert){
			printf("===================GetEncCert===========================\n");
			dumpcrt(issued_enccert);
			printf("===================success===========================\n");
			memset(path, 0, sizeof(path));
			snprintf(path, sizeof(path), "./kpool/%s.enc.scep.crt.pem", p[n]);
			ret = FILE_putcontent((const unsigned char *)cysec_x509crt_as_pem(issued_enccert), strlen(cysec_x509crt_as_pem(issued_enccert)), path);
			if(ret)
				goto freebuffer;	
		}
		enc_pvk = cysec_scep_response_certrep_get_enc_pvk(rsp);
		if(enc_pvk){
			printf("===================GetEncPvk===========================\n");
			dumpkey(enc_pvk);
			printf("===================success===========================\n");
			memset(path, 0, sizeof(path));
			snprintf(path, sizeof(path), "./kpool/%s.enc.scep.pvk.pem", p[n]);

			ret = cysec_pkey_export_privatekey(enc_pvk, &enc_pvk_buf, &enc_pvk_buf_len, PEM);
			if(ret)
				goto freebuffer;

			ret = FILE_putcontent(enc_pvk_buf, enc_pvk_buf_len, path);
			if(ret)
				goto freebuffer;	
		}
#endif

freebuffer:
		if(cm)
			certmgr_free(cm);
		if(issuedcert)
			cysec_x509crt_free(issuedcert);

		SAFE_FREE(enc_pvk_buf);
		SAFE_FREE(pem);
		SAFE_FREE(rsp_der);
		if(local_pctx)
			cysec_pkey_free(local_pctx);
		if(local_crt)
			cysec_x509crt_free(local_crt);
		if(cacert)
			cysec_x509crt_free(cacert);
		if(rsp)
			cysec_scep_response_free(rsp);
#ifndef CYSEC_NO_CNCAV1_1
		if(issued_enccert)
			cysec_x509crt_free(issued_enccert);
		if(enc_pvk)
			cysec_pkey_free(enc_pvk);
#endif
	}
}

int main(void)
{
	test_scep_respond(0);
	//test_scep_request(0);
	//test_scep_respond(1);
	//test_scep_request(1);
	exit(0);
}
#else
int  main()
{
	return 0;
}

#endif //!(CYSEC_NO_SCEP) && !(CYSEC_NO_TLS)
