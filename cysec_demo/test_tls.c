#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <cysec.h>
#include "test_util.h"

#ifndef CYSEC_NO_TLS

static int tls_vcm_cb(X509CRT_PCTX crt, void *userdata){
	CERTMGR_PCTX cm = (CERTMGR_PCTX)userdata;
	int ret;

	if(!crt || !cm)
		return -1;

	//printf("tls server certificate:\n");
	//dumpcrt(crt);
	ret = cysec_certmgr_verify(cm, crt);
	s_assert((ret == 0), "Verify Certificate Chain Failure, ret = %08x\n", ret);
    if(ret) {
        return -(0x0000FFFF & ret);        
    }

    ret = cysec_certmgr_add_ca(cm, crt);
   	s_assert((ret == 0), "Add Certificate Chain Failure, ret = %08x\n", ret);
    if(ret) {
        return -(0x0000FFFF & ret);        
    }

	return ret;
}

#if 0
static void test_ssl_one(void) {
	const char* p[] = { "rsa", "sm2", "ecc" };
	char path[256];
	unsigned int n, m; 
	int ret;
	int num;
	PKEY_PCTX pvk = NULL;
	X509CRT_PCTX crt = NULL;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("tls client test ...\n");
	for (n = 0; n < sizeof(p)/sizeof(char*); n ++) {
		for (m = 0; m < 2; m ++) {
			TLS_CLIENT_PCTX ctx = tls_client_new();
			tls_client_set_verify_callback(ctx, tls_vcb, NULL);
			if (m) {
				snprintf(path, sizeof(path), "%s/%s.ssl.pvk.pem", KPOOL_PATH, p[n]);
				pvk = FILE_getpvk(path);
				snprintf(path, sizeof(path), "%s/%s.ssl.crt.pem", KPOOL_PATH, p[n]);
				crt = FILE_getcrt(path);

				ret = tls_client_set_certificate(ctx, crt);
				s_assert((ret == 0), "ret=%08x", ret);
				ret = tls_client_set_private_key(ctx, pvk);
				s_assert((ret == 0), "ret=%08x", ret);
			}
			
			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

			tls_client_free(ctx);
			
			if (m) {
				x509crt_free(crt);
				pkey_free(pvk);
			}
		}
	}
}
#endif

static void test_ssl_benchmark_verify_none(const char *srvaddr, int port) {
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";
	int ret = 0 ;
	size_t reqlen = strlen(req);
	const char *addr = NULL;

	if(!srvaddr)
		addr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
	else
		addr = srvaddr;

	printf("using remote server %s:%d.\n", addr, port);
	

	benchmark(1);
	while (_bm.loop) {
		TLS_CLIENT_PCTX ctx = tls_client_new();

		ret = tls_client_connect(ctx, addr, port);
		if (ret) {
			printf("connect failed. exit!(%08x)\n",ret);
			exit (-1);
		}

		ret = tls_client_write(ctx, (const unsigned char *)req, reqlen);
		if (ret<=0) {
			printf("write req data failed. exit!\n");
			exit (-1);
		}
		tls_client_close(ctx);
		tls_client_free(ctx);
		_bm.round ++;
	}
	benchmark(0);

	printf("tls client\ttime=%fs round=%d  %.2f/s\n", _bm.e, _bm.round, _bm.round/_bm.e);
}

static void test_ssl_benchmark_verify_required(const char *srvaddr, int port, CERTMGR_PCTX cm, X509CRT_PCTX localcrt, PKEY_PCTX localpvk) {
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";
	int ret = 0 ;
	size_t reqlen = strlen(req);
	const char *addr = NULL;

	if(!cm || !localcrt || !localpvk)
		return ;

	if(!srvaddr)
		addr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
	else
		addr = srvaddr;

	printf("using remote server %s:%d.\n", addr, port);
	
	benchmark(1);
	while (_bm.loop) {
		TLS_CLIENT_PCTX ctx = tls_client_new();
		
		ret = tls_client_set_certificate(ctx, localcrt);
		s_assert((ret == 0), "ret=%08x", ret);
		ret = tls_client_set_private_key(ctx, localpvk);
		s_assert((ret == 0), "ret=%08x", ret);	

		tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

		ret = tls_client_connect(ctx, addr, port);
		if (ret) {
			printf("connect failed. exit!(%08x)\n",ret);
			cysec_tls_client_free(ctx);
			return;
		}
			
		ret = tls_client_write(ctx, (const unsigned char *)req, reqlen);
		if (ret<=0) {
			printf("write req data failed. exit!\n");
			tls_client_close(ctx);
			tls_client_free(ctx);
			return;
		}
		tls_client_close(ctx);
		tls_client_free(ctx);
		_bm.round ++;
	}
	benchmark(0);

	printf("tls client\ttime=%fs round=%d  %.2f/s\n", _bm.e, _bm.round, _bm.round/_bm.e);

}

static int test_ssl_benchmark(void)
{
	const char* p[] = { "rsa", "sm2", "ecc" };
	char path[256];
	unsigned int n; 
	PKEY_PCTX pvk = NULL;
	X509CRT_PCTX crt = NULL;
	X509CRT_PCTX cacrt = NULL;
	X509CRT_PCTX rootcrt = NULL;
	CERTMGR_PCTX cm = NULL;
	const char* srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";

	printf("tls client test ...\n");
	for (n = 0; n < sizeof(p)/sizeof(char*); n ++) {
		test_ssl_benchmark_verify_none(srvaddr, 443+n*2);
	}

	
	for (n = 0; n < sizeof(p)/sizeof(char*); n ++) {

		snprintf(path, sizeof(path), "%s/%s.ssl.rootcrt.pem", KPOOL_PATH, p[n] );
		rootcrt = FILE_getcrt(path);

		snprintf(path, sizeof(path), "%s/%s.ssl.cacrt.pem", KPOOL_PATH, p[n] );
		cacrt = FILE_getcrt(path);

		snprintf(path, sizeof(path), "%s/%s.ssl.pvk.pem", KPOOL_PATH, p[n]);
		pvk = FILE_getpvk(path);
		snprintf(path, sizeof(path), "%s/%s.ssl.crt.pem", KPOOL_PATH, p[n]);
		crt = FILE_getcrt(path);

		cm = certmgr_new();
		certmgr_add_ca(cm, cacrt);
		certmgr_add_ca(cm, rootcrt);

		test_ssl_benchmark_verify_required(srvaddr, 443+n*2+1,cm,crt,pvk);	

		pkey_free(pvk);
		x509crt_free(cacrt);
		x509crt_free(crt);
		x509crt_free(rootcrt);
		certmgr_free(cm);
	}

	return 0;
}

/** for testing usage, don't use for product.*/
static int test_ocspstapling_callback(X509CRT_PCTX ctx, unsigned char *ocspresponse, int olen, void *userdata)
{
	CERTMGR_PCTX cm = (CERTMGR_PCTX)userdata;
	OCSP_RESPONSE_PCTX rsp_ctx = NULL;
	X509CRT_PCTX signer = NULL;	
	unsigned int ocspstatus = 0, ocsp_certstatus = 0;
	int ret = -1;

	if( !ctx || !ocspresponse || olen <= 0 )
		return -1;

	ret = cysec_ocsprsp_decode(ocspresponse, olen, &rsp_ctx);
	s_assert((ret == 0), "recevice an invalid OCSP response, %08x\n",ret);
	if(ret != 0 ) goto err;;

	signer = cysec_ocsprsp_get_signer(rsp_ctx);
	if(!signer)
		signer = cysec_certmgr_get_ocsprsp_signer(cm, rsp_ctx);

    if(!signer) {
        ret = CYSEC_E_OCSP_CERTIFICATE_NOT_FOUND;
        goto err;
    }

	ret = cysec_ocsprsp_verify(rsp_ctx,signer);
	s_assert((ret == 0), "Verify Signature Failure, ret = %08x\n", ret);
	if(ret !=0 ) goto err;

	if(cm) {
		ret = cysec_certmgr_verify(cm, signer);
		s_assert((ret == 0), "Verify Certificate Chain Failure, ret = %08x\n", ret);
		if( ret != 0 ) goto err;		
	}

	ret = cysec_ocsprsp_get_rspstatus(rsp_ctx, &ocspstatus);
	s_assert((ret == 0), "failed to get rsp status %08x\n",ret);
	printf("rspstatus is %d\n",ocspstatus);
	if(ret != 0 || ocspstatus != 0) {
        ret = CYSEC_E_OCSP_RETURN_STATUS;
        goto err;
	}

	ret = cysec_ocsprsp_get_certstatus(rsp_ctx, ctx, cm, &ocsp_certstatus);
	s_assert((ret == 0), "failed to get cert status %08x\n", ret);
	printf("certstatus is %d\n", ocsp_certstatus);
    if(ret != 0) {
        //failf(data, "SSL: Failed to get server status %08X\n", ret);
        goto err;
    }

    if(ocsp_certstatus != 0) {
        //failf(data, "SSL: the server's certstatus is %08x\n", ocsp_certstatus);
        if(ocsp_certstatus == 1)
            ret = CYSEC_E_OCSP_REVOKED;
        else
            ret = CYSEC_E_OCSP_UNKNOWN;
        goto err;
    }

	if(signer)
		x509crt_free(signer);
	if(rsp_ctx)
		cysec_ocsprsp_free(&rsp_ctx);
	return 0;
err:
	if(signer)
		x509crt_free(signer);
	if(rsp_ctx)
		cysec_ocsprsp_free(&rsp_ctx);

    return -(0x0000FFFF & ret);
}

/** ocsp stapling */
static void test_nonblocking_ssl_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (NONBLOCKING socket) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			TLS_CLIENT_PCTX ctx = NULL;
			
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;

			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			
			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

/** ocsp stapling */
static void test_blocking_ssl_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (BLOCKING socket) ...\n");
	printf("==================================\n");

	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			TLS_CLIENT_PCTX ctx =NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;


			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_block_mode(ctx, CYSEC_TLS_CLIENT_BLOCK_MODE_BLOCK);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_rwtimeout(ctx, 5);
			if(ret)
				goto freebuffer;

			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

static void test_ssl_revoked_nonblocking_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (NONBLOCKING socket)(certificate revoked) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			TLS_CLIENT_PCTX ctx=NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.revoke_crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.revoke_pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;


			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			if(ret)
				goto freebuffer;
			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

static void test_ssl_revoked_blocking_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";


	printf("==================================\n");
	printf("tls client is testing (BLOCKING socket)(certificate revoked) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			PKEY_PCTX pvk = NULL;
			X509CRT_PCTX rootcrt = NULL;
			TLS_CLIENT_PCTX ctx = NULL;
			char path[256] = {0};
			
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.revoke_crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.revoke_pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;


			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_block_mode(ctx, CYSEC_TLS_CLIENT_BLOCK_MODE_BLOCK);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_rwtimeout(ctx, 5);
			if(ret)
				goto freebuffer;

			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

static void test_ssl_expired_nonblocking_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (NONBLOCKING socket)(certificate expired) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			TLS_CLIENT_PCTX ctx = NULL;
			
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.expire_crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.expire_pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;


			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			if(ret)
				goto freebuffer;
			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:

			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

static void test_ssl_expired_blocking_certstatus(void) {
	const char* p[] = { "rsa", "sm2", "ecc"};
	unsigned int n, m; 
	int ret;
	int num;
	const char* srvaddr = NULL;
	const char* req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";

	printf("==================================\n");
	printf("tls client is testing (BLOCKING socket)(certificate expired) ...\n");
	printf("==================================\n");
	for (n = 0; n < sizeof(p)/sizeof(char*);  n ++) {
		for (m = 0; m < 2; m ++) {
			CERTMGR_PCTX cm = NULL;
			X509CRT_PCTX cacrt = NULL;
			X509CRT_PCTX crt = NULL;
			X509CRT_PCTX rootcrt = NULL;
			PKEY_PCTX pvk = NULL;
			char path[256] = {0};
			TLS_CLIENT_PCTX ctx = NULL;
			
			printf("=========================================================\n");
			snprintf(path, sizeof(path), "./kpool/%s.ssl.expire_crt.pem", p[n]);
			crt = FILE_getcrt(path);
			if(!crt)
				goto freebuffer;

			printf("========(%s)========\n", path);
			snprintf(path, sizeof(path), "./kpool/%s.ssl.rootcrt.pem", p[n] );
			rootcrt = FILE_getcrt(path);
			if(!rootcrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.cacrt.pem", p[n] );
			cacrt = FILE_getcrt(path);
			if(!cacrt)
				goto freebuffer;

			snprintf(path, sizeof(path), "./kpool/%s.ssl.expire_pvk.pem", p[n]);
			pvk = FILE_getpvk(path);
			if(!pvk)
				goto freebuffer;

			cm = certmgr_new();
			if(!cm)
				goto freebuffer;
			ret = certmgr_add_ca(cm, cacrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;
			ret = certmgr_add_ca(cm, rootcrt);
			s_assert((ret == 0), "ret=%08x\n", ret);
			if(ret)
				goto freebuffer;


			ctx = tls_client_new();
			if(!ctx)
				goto freebuffer;
			cysec_tls_client_set_ocspstapling_callback(ctx, test_ocspstapling_callback, (void *)cm);
			tls_client_set_verify_callback(ctx, tls_vcm_cb, (void *)cm);

			ret = tls_client_set_certificate(ctx, crt);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			ret = tls_client_set_private_key(ctx, pvk);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_block_mode(ctx, CYSEC_TLS_CLIENT_BLOCK_MODE_BLOCK);
			if(ret)
				goto freebuffer;

			ret = cysec_tls_client_set_rwtimeout(ctx, 5);
			if(ret)
				goto freebuffer;

			srvaddr = getenv("TLS_SERVER_ADDR") ? getenv("TLS_SERVER_ADDR") : "192.168.10.130";
			printf("connecting %s:%d \n", srvaddr, 443+n*2+m);
			ret = tls_client_connect(ctx, srvaddr, 443+n*2+m);
			s_assert((ret == 0), "ret=%08x", ret);
			if(ret)
				goto freebuffer;
			
			num = tls_client_write(ctx, (const unsigned char *)req, strlen(req));
			s_assert((num == (int)strlen(req)), "num=%08x (%zu)", num, strlen(req));
			printf("connected.\n");

			tls_client_close(ctx);
			printf("closed. %d \n\n", 443+n*2+m);

		freebuffer:
			if(ctx)
				tls_client_free(ctx);
			
			if(crt)
				x509crt_free(crt);

			if(pvk)
				pkey_free(pvk);

			if(cacrt)
				x509crt_free(cacrt);
			
			if(rootcrt)
				x509crt_free(rootcrt);
			
			if(cm)
				certmgr_free(cm);
			printf("=========================================================\n");

		}
	}
}

int main(void)
{

	test_nonblocking_ssl_certstatus();
	
	test_blocking_ssl_certstatus();


	test_ssl_revoked_nonblocking_certstatus();
	test_ssl_revoked_blocking_certstatus();
	test_ssl_expired_nonblocking_certstatus();
	test_ssl_expired_blocking_certstatus();
	//test_ssl_one();
	test_ssl_benchmark();
	return 0;
}

#else
int  main()
{
	return 0;
}

#endif //CYSEC_NO_TLS