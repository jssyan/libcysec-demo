#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include <cysec.h>
#include "util.h"

#ifdef ANDROID
#include <android/log.h>
#define LOG_DEBUG ANDROID_LOG_DEBUG
#define LOG_INFO ANDROID_LOG_INFO
#define LOG_WARNING ANDROID_LOG_WARN
#define LOG_ERR ANDROID_LOG_ERROR
#define LOG_CRIT    ANDROID_LOG_FATAL
#define LOG_TAG "demo"

#ifdef DEBUG
#define slog(level, fmt, args...) do {\
        __android_log_print(level, LOG_TAG, fmt, ##args);\
    } while(0)
#else
#define slog(level, fmt, args...) do{;} while(0)
#endif /* LIBCCURL_DEBUG */

#else /* ANDROID */
#include <syslog.h>

#ifdef DEBUG
#define slog(level, fmt, args...) do {\
        openlog("libccurl", LOG_CONS|LOG_PID,0);\
        syslog(level, fmt, ##args);\
        closelog();\
    } while(0)
#else
#define slog(level, fmt, args...) do{;} while(0)
#endif /* LIBCCURL_DEBUG */

#endif /* ANDROID */

#ifdef DEBUG
static void
cysec_debug(void *context, int level, const char *f_name, int line_nb,
            const char *line)
{
    time_t timep;
    FILE *fp = NULL;

    if (!context)
        return;

    time(&timep);
    printf("%s %s:%04d: %s", ctime(&timep), f_name, line_nb, line);
}
#endif /* DEBUG */

#ifndef CYSEC_NO_TLS

long inc_time = 0; 

/** 此DEMO 展示通过SSL双向认证 */
/** 单向支持OCSP Stapling, 验证服务端证书 */

/* 获取文件内容 */
static unsigned char* FILE_getcontent(const char* fname, size_t* len) {
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
  	*len = l;
	}
  fclose(fp);
  return r;
}


/** 打印证书数据 */
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

/** 打印密钥数据 */
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

/** 解析证书文件到证书句柄 */
static X509CRT_PCTX FILE_getcrt(const char* fname) {
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

/** 解析私钥到证书句柄 */
static PKEY_PCTX FILE_getpvk(const char* fname) {
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

#if 0
/** 证书链验证回调函数 */
static int tls_vcm_cb(X509CRT_PCTX crt, void *userdata){
	CERTMGR_PCTX cm = (CERTMGR_PCTX)userdata;
	int ret;

	if(!crt || !cm)
		return 0;

	ret = cysec_certmgr_verify(cm, crt);
	s_assert((ret == 0), "Verify Certificate Chain Failure, ret = %08x\n", ret);
	if(ret)
    	return -(0x0000FFFF & ret);

    return 0;
}
#endif

static int tls_vcm_cb_ex(X509CRT_PCTX crt, void *userdata, unsigned int *flags)
{
    CERTMGR_PCTX cm = (CERTMGR_PCTX)userdata;
    int ret;

    if(!crt || !cm)
        return 0;

    ret = cysec_certmgr_verify_ex(cm, crt, flags);
    if(ret != 0) {
        /* failf(data, "SSL: Verify SSL Server Certificate 
        Chain error, ret = %08x\n", ret); */
        return -(0x0000FFFF & ret);
    }

    /* 加入完整信任链到可信列表中 */
    ret = cysec_certmgr_add_ca(cm, crt);
    if(ret) {
        return -(0x0000FFFF & ret);        
    }

    return 0;
}

/** 验证OCSP STAPLING 回调函数 */
static int tls_ocspstapling_verify_cb(X509CRT_PCTX ctx, unsigned char *ocspresponse, int olen, void *userdata)
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

/** 外部建立socket 连接，方便设置各种自定义属性 */
static int tcp_connect(const char* host, int port, int *sockfd) {
	const char* peer = host;
	struct hostent* entry = gethostbyname(peer);
	int flags = 0;
	int ret = 0;
	int on = 1;

	if( !host || !sockfd || port <= 0 )
		return -1;

	if (!entry) {
		return -1;
	}

	struct sockaddr_in tmp;
	memset(&tmp, 0, sizeof(struct sockaddr_in));
	tmp.sin_family = AF_INET;
	tmp.sin_port = htons((short)port);
	memcpy(&tmp.sin_addr.s_addr, entry->h_addr_list[0],entry->h_length);

	int r = socket(AF_INET, SOCK_STREAM, 0);
	if (r < 0) {
		return r;
	}

	ret = connect(r, (const struct sockaddr*)&tmp, sizeof(tmp));
	if(ret != 0)
		return ret; /* can't connect */
	
	/** set non block */
	flags = fcntl(r, F_GETFL, 0);
	if(flags < 0)
		return flags;

	ret = fcntl(r, F_SETFL, flags | O_NONBLOCK);
	if(ret < 0 )
		return ret;

	ret = setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on));
	if(ret < 0)
		return ret;

	*sockfd = r;
	return 0;
}

#ifndef INT_MAX
#define INT_MAX 2147483646
#endif
#define TLS_READ_AGAIN 1
#define TLS_READ_ERROR 2
#define TLS_ERROR_TIMEOUT 3
#define TLS_ERROR_PEER_CLOSE_NOTIFY 4
#define TLS_ERROR_NET_CONN_RESET 5
#define TLS_ERROR_CONN_EOF 6

/* SSL 读数据 */
static int tls_read(TLS_CLIENT_PCTX ctx, unsigned char *buf, size_t buflen, int *errorcode)
{
	char error_buffer[CYSEC_TLS_CLIENT_ERROR_STRING_MAX_SZ];
	int buffsize = (buflen > (size_t)INT_MAX)?INT_MAX:(int)buflen;
	int nread = cysec_tls_client_read(ctx, buf, buffsize);

	if(nread < 0) {
		int err = cysec_tls_client_get_sslerror(ctx, nread);
		switch(err){
	        case SSL_ERROR_PEER_CLOSE_NOTIFY: /* no more data */
	        	*errorcode = TLS_ERROR_PEER_CLOSE_NOTIFY;
	            nread = 0;
	            break;
	        case SSL_ERROR_NET_CONN_RESET:
	        	*errorcode = TLS_ERROR_NET_CONN_RESET;
	        	nread = 0;
	        	break;
	        case SSL_ERROR_CONN_EOF:
	        	*errorcode = TLS_ERROR_CONN_EOF;
	        	nread = 0;
	        	break;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				*errorcode = TLS_READ_AGAIN;
				return nread;
			default:
				printf("SSL read:%s, errno %d",cysec_tls_client_get_sslerror_string(err,error_buffer), nread);
				*errorcode = TLS_READ_ERROR;
				return nread; 
		}
	}
	return nread;
}

#define TLS_WRITE_AGAIN 1
#define TLS_WRITE_ERROR 2

/** SSL写数据 */
static int tls_write(TLS_CLIENT_PCTX ctx, const unsigned char *buf, size_t buflen, int *errorcode)
{
	char error_buffer[CYSEC_TLS_CLIENT_ERROR_STRING_MAX_SZ];
	int buffsize = (buflen > (size_t)INT_MAX)?INT_MAX:(int)buflen;
	int nread = cysec_tls_client_write(ctx, buf, buffsize);

	if(nread < 0) {
		int err = cysec_tls_client_get_sslerror(ctx, nread);
		switch(err){
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				*errorcode = TLS_WRITE_AGAIN;
				return nread;
			default:
				printf("SSL write:%s, errno %d",cysec_tls_client_get_sslerror_string(err,error_buffer), nread);
				*errorcode = TLS_WRITE_ERROR;
				return nread; 
		}
	}
	return nread;
}

static void usage(void)
{
	printf("This demo shows how to establish an SSL connection and send data and receive data during some time.\n");
	printf("--capath the path of CA certificate.\n");
	printf("--cafile the filename of CA certificate.\n");
	printf("--host the IP/domain of SSL server.\n");
	printf("--port the port of SSL server.\n");
	printf("--cert the local certificate.\n");
	printf("--pvk the local key.\n");
	printf("--inc_ocsp_valid_time increase ocsp valid time.\n");
	printf("--recv_timeout timeout for recevice, default 5 seconds.\n");
	printf("--sslversion cncav1.1 or tlsv1.2.\n");
#ifndef CYSEC_NO_CNCAV1_1
	printf("--enccert the local encryption certificate(only for cncav1.1).\n");
	printf("--encpvk the local encryption pvk(only for cncav1.1).\n");
#endif
#ifdef CYSEC_TLS_DEBUG
	printf("--debug print debug message .(only on dbg version).\n");
#endif
	printf("--help print this message.\n");
	printf("--runtime time for testing seconds(default 10 seconds).\n");
	exit(0);
}

static double get_current_time(void){
	struct timeval tv;
	gettimeofday(&tv, 0);

	return (double)tv.tv_sec + (double)tv.tv_usec/1000000;
}

int main(int argc, char **argv)
{
	int ret = -1, reserr = -1;
	CERTMGR_PCTX	cm = NULL;
	X509CRT_PCTX	cacert = NULL, local_crt = NULL, local_enccrt = NULL;
	PKEY_PCTX local_pvk = NULL, local_encpvk = NULL;
	TLS_CLIENT_PCTX	tls_ctx = NULL;
	char message[] = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";
	unsigned char read[4096] = {0};
	const char *host = NULL, *cafile = NULL, *capath = NULL, *local_crt_file = NULL, 
		*local_pvk_file = NULL, *version = NULL, *local_enccrt_file = NULL, *local_encpvk_file = NULL;
	int ver = CYSEC_TLS_VERSION_TLS1_2;
	int port = 0;
	int sockfd = -1;
	int rc = 0;
	int errorcode = 0;
	size_t sent_counts = 0;
	long timeout = 5;
	char error_buffer[CYSEC_TLS_CLIENT_ERROR_STRING_MAX_SZ];
#ifdef DEBUG
	int debug = 0;
#endif
	long runtime = 10;
	double b, e; 

	argc--;
	argv++;

	while(argc > 0){
		if(strcmp(*argv,"--capath") == 0){
		  if(--argc<1)
		    break;
		  capath = *(++argv);
		}
		else if(strcmp(*argv,"--cafile") == 0){
		  if(--argc<1)
		    break;
		  cafile = *(++argv);
		}else if(strcmp(*argv,"--host") == 0){
		  if(--argc<1)
		    break;
		  host = *(++argv);
		} else if(strcmp(*argv,"--port") == 0) {
		  if(--argc<1)
		    break;
		  port = atoi(*(++argv));
		} else if(strcmp(*argv,"--cert") == 0){
		  if(--argc<1)
		    break;
		  local_crt_file = *(++argv);
		} else if(strcmp(*argv,"--pvk") == 0){
		  if(--argc<1)
		    break;
		  local_pvk_file = *(++argv);
		} else if(strcmp(*argv,"--enccert") == 0){
		  if(--argc<1)
		    break;
		  local_enccrt_file = *(++argv);
		} else if(strcmp(*argv,"--encpvk") == 0){
		  if(--argc<1)
		    break;
		  local_encpvk_file = *(++argv);
		} else if(strcmp(*argv, "--inc_ocsp_valid_time") == 0 ) {
			if(--argc < 1)
				break;
			inc_time = atol(*(++argv));
		} else if(strcmp(*argv, "--recv_timeout") == 0 ) {
			if(--argc <1)
				break;
			timeout = atol(*(++argv));
		} else if(strcmp(*argv,"--sslversion") == 0) {
			if(--argc < 1)
				break;

			version = *(++argv);
			if(strcmp(version,"tlsv1.2") == 0)
			{
				ver = CYSEC_TLS_VERSION_TLS1_2;
#ifndef CYSEC_NO_CNCAV1_1
			} else if(strcmp(version,"cncav1.1") == 0) {
				ver = CYSEC_TLS_VERSION_CNCA1_1;
#endif
			}else {
				printf("unsupport ssl protocol %s.\n", version);
				usage();
			}
		} else if(strcmp(*argv, "--help") == 0) {
			usage();
		}
#ifdef DEBUG
		else if(strcmp(*argv, "--debug") == 0) {
			argv++;
			argc--;
			debug = 1;
		}
#endif
		else if(strcmp(*argv, "--runtime") == 0) {
			if(--argc < 1)
				break;

			runtime = atol(*(++argv));			
		}
		else {
			argc--;
			argv++;
		}
	}

  if(!host||port == 0)
    usage();

	if(cafile) {
		cacert = FILE_getcrt(cafile);
		if(!cacert){
			printf("the CA file(%s) is an invalid X509's certificate.\n", capath);
			goto err;
		}		
	}

	if(local_crt_file)
	{
		local_crt = FILE_getcrt(local_crt_file);
		if(!local_crt) {
			printf("the local certificate (%s) is an invalid X509's certificate.\n", local_crt_file);
			goto err;				
		}
	}

	if(local_pvk_file)
	{
		local_pvk = FILE_getpvk(local_pvk_file);
		if(!local_pvk) {
			printf("the local private key (%s) is an invalid private key .\n", local_pvk_file);
			goto err;
		}		
	}

	if(ver == CYSEC_TLS_VERSION_CNCA1_1) {
		if(local_enccrt_file)
		{
			local_enccrt = FILE_getcrt(local_enccrt_file);
			if(!local_enccrt) {
				printf("the local encryption certificate (%s) is an invalid X509's certificate.\n", local_enccrt_file);
				goto err;				
			}
		}

		if(local_encpvk_file)
		{
			local_encpvk = FILE_getpvk(local_encpvk_file);
			if(!local_encpvk) {
				printf("the local encryption private key (%s) is an invalid private key .\n", local_encpvk_file);
				goto err;
			}		
		}		
	}
	/** 构造证书管理器 */
	cm = cysec_certmgr_new();
	if(!cm){
		printf("out of memory.\n");
		goto err;
	}

	if(cacert) {
		/** 证书管理器加入CA证书  */
		ret = cysec_certmgr_add_ca(cm, cacert);
		if(ret) {
			printf("the CA certificate is an invalid X509's certificate, error(%08X).\n", ret);
			goto err;
		}		
	}

	if(capath) {
		ret = cysec_certmgr_add_capath(cm, capath);
		if(ret) {
			printf("failed to add capath(%s), error(%08X).\n", capath, ret);
			goto err;			
		}
	}

	/** 构造TLS 客户端句柄 */
	tls_ctx = cysec_tls_client_new();
	if(!tls_ctx){
		printf("out of memory.\n");
		goto err;
	} 
	
	ret = cysec_tls_client_set_version(tls_ctx, ver);
	if(ret){
		printf("Failed to set version, error(%08X).\n", ret);
		goto err;
	}

    ret = cysec_tls_client_check_domain_name(tls_ctx, host);
    if(ret != 0) {
        printf("unable to check domain name .\n");
        goto err;
    }

	/** 设置证书链验证回调 */
	ret = cysec_tls_client_set_verify_callback_ex(tls_ctx, tls_vcm_cb_ex, (void *)cm);
	if(ret){
		printf("set vcm callback error. error=(%08X).\n", ret);
		goto err;
	}

	/** 设置OCSP回调 */
	ret = cysec_tls_client_set_ocspstapling_callback(tls_ctx, tls_ocspstapling_verify_cb, (void *)cm);
	if(ret){
		printf("set ocspstapling error, error=(%08X).\n", ret);
		goto err;
	}

	if(local_crt){
		ret = cysec_tls_client_set_certificate(tls_ctx, local_crt);
		if(ret){
			printf("set local certificate error (%08X)\n",ret);
			goto err;
		}
	}

	if(local_pvk){
		ret = cysec_tls_client_set_private_key(tls_ctx, local_pvk);
		if(ret){
			printf("set local private key error (%08X)\n",ret);
			goto err;
		}
	}

#ifndef CYSEC_NO_CNCAV1_1
	if(ver == CYSEC_TLS_VERSION_CNCA1_1) {
		if(local_enccrt){
			ret = cysec_tls_client_set_enc_certificate(tls_ctx, local_enccrt);
			if(ret){
				printf("set local encryption certificate error (%08X)\n",ret);
				goto err;
			}
		}

		if(local_encpvk){
			ret = cysec_tls_client_set_enc_private_key(tls_ctx, local_encpvk);
			if(ret){
				printf("set local encryption private key error (%08X)\n",ret);
				goto err;
			}
		}
	}
#endif
	ret = tcp_connect(host, port ,&sockfd);
	if( ret ){
		printf("connect the host(%s)(%d) error(%d)\n", host, port, ret);
		goto err;
	}
#ifdef DEBUG
	if(debug) {
		ret = cysec_tls_client_enable_debug(tls_ctx, cysec_debug, tls_ctx, 4);
		if(ret){
	        printf("SSL:cysec_tls_client_enable_debug error (%08x).\n", ret);
	        goto err;
	    }		
	}
#endif /* CYSEC_TLS_DEBUG */

	ret = cysec_tls_client_set_fd(tls_ctx, sockfd);
	if( ret )
		goto err;

	ret = cysec_tls_client_ssl_setup_conf(tls_ctx);
	if(ret)
		goto err;

	ret = cysec_tls_client_ssl_connect(tls_ctx);
	if(ret != 0){
		ret = cysec_tls_client_get_sslerror(tls_ctx, ret);
		if( ret == SSL_ERROR_FATAL )
		{
			ret = cysec_tls_client_get_alert_code(tls_ctx);
			printf("got alert %08x\n",ret);
		}
		else if(ret == CYSEC_E_TLSCLIENT_X509_CERT_VERIFY_FAILED){
			ret =  cysec_tls_client_get_verify_result(tls_ctx);
            if(ret) {
            	printf("SSL_connect failed due to verify error %08X: %s\n", ret,
                  cysec_tls_client_get_verify_result_string(ret, error_buffer, sizeof(error_buffer)));
				goto err;
            }
		} else {
			printf("SSL connect error, ret(%08X): %s\n",ret, cysec_tls_client_get_sslerror_string(ret, error_buffer));
			goto err;
		}
	}

	b =get_current_time();
	while(1) {
		struct timeval tv;
		fd_set read_fds, write_fds;

select_again:
		e = get_current_time();
		if((e-b) > runtime){
			break;
		}
		FD_ZERO( &read_fds );
		FD_ZERO( &write_fds);
		FD_SET ( sockfd, &write_fds);
		FD_SET ( sockfd, &read_fds );

		tv.tv_sec = timeout ;
		tv.tv_usec = 0 ;


		ret = select(sockfd+1, &read_fds, &write_fds, NULL, &tv);
		if(ret == 0){
			printf("select timeout .\n");
			goto err;
		}

		if(ret < 0)
		{
			if( errno == EINTR) {
				printf("errno is EINTR.\n");
				continue;
			}

			goto err;
		}

		if(ret > 0 && FD_ISSET(sockfd, &write_fds)) {
			while(1)
			{
				/** 写数据 */
				rc = tls_write(tls_ctx,(const unsigned char *)message + sent_counts, sizeof(message) - sent_counts, &errorcode);
				/** 如果没写完，继续写 */
				if(rc > 0 && rc < (int)(sizeof(message) - sent_counts )){
					printf("Sent: (%s)(%d)\n", message + sent_counts, rc);
					sent_counts += rc;
					continue;
				}
				/*  如果写完，跳出 */
				else if(rc > 0 && (rc == (int)(sizeof(message) - sent_counts))){
					printf("Sent: (%s)(%zu)\n", message + sent_counts, sent_counts);
					break;
				}
				/* 重新写一次 */
				else if(rc < 0 && errorcode == TLS_WRITE_AGAIN)
					continue;
				/** 报错 */
				else if (rc < 0 && errorcode == TLS_WRITE_ERROR){
					ret = rc;
					goto err;
				}else
					break;
			}			
		}

		if(ret > 0 && FD_ISSET(sockfd, &read_fds)) {
			int err_count = 0;
			/** 读数据 */
read_again:
			rc = tls_read(tls_ctx, (unsigned char *)read , sizeof(read), &errorcode );
			/** 如果读到数据 ,则继续读 */
			if(rc > 0 && rc == sizeof(read)){
				printf("receviced:(%d)\n" , rc);
				hexdump(read, rc);
				goto read_again;
			} else if (rc > 0 && (unsigned int)rc < sizeof(read)) {
				printf("receviced:(%d)\n",rc);
				hexdump(read,rc);
				goto select_again;
			}
			/** 网络管道中断 */
			else if ( rc == 0 ) {
				printf("no data or peer close socket.\n ");
				goto select_again;
			}
			/** 重读 */
			else if(rc < 0 && errorcode == TLS_READ_AGAIN){
				err_count ++;
				if(err_count > 10){
					goto err;
				}
				else
					goto read_again;
			}
			/** 出错 */
			else if (rc < 0 && errorcode == TLS_READ_ERROR){
				ret = rc;
				goto err;
			/** 网络超时 */
			} else if(rc <0 && errorcode == TLS_ERROR_TIMEOUT) {
				printf("timeout.\n");
				ret = rc;
				goto err;
			} else {
				printf("error.(%d)\n", rc);
				goto err;
			}

		}
	}
	/** 关闭SSL隧道(不关闭socket fd) */
	cysec_tls_client_shutdown(tls_ctx);
	tls_client_free(tls_ctx);
	tls_ctx = NULL;
	close(sockfd);
	sockfd = -1;
	reserr = 0;
	
err:
	if(cacert)
		cysec_x509crt_free(cacert);
	if(local_crt)
		cysec_x509crt_free(local_crt);
	if(local_pvk)
		cysec_pkey_free(local_pvk);
	if(local_enccrt)
		cysec_x509crt_free(local_enccrt);
	if(local_encpvk)
		cysec_pkey_free(local_encpvk);
	if(cm)
		certmgr_free(cm);
	if(tls_ctx)
		tls_client_free(tls_ctx);
	if(sockfd != -1)
		close(sockfd);

	return reserr;
}

#else
int  main()
{
	return 0;
}
#endif //CYSEC_NO_TLS


