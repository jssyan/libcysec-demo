/**
 * shows https usage with Curl(Base on CysecSDK).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
 
#include <curl/curl.h>

#include <cysec.h>
#ifndef DO_NOT_USE_PKI_CM_CALLBACK
#include <pki_cm_callback.h>
#endif
#include "vpk_util.h"
#include "util.h"

#ifdef HAVE_PK_CUSTOM_SUPPORT 
long verbose = 0;
long timeout = 10L;
long connecttimeout = 5L;
const char *debugfile = NULL;
struct trace_data config;
int debugascii = 0;
const char *version = NULL;
long ver = CURL_SSLVERSION_TLSv1_2;
int envelop = 1;

#ifndef DO_NOT_USE_PKI_CM_CALLBACK
/* 
   **** This example only works with libcurl base on CysecSDK  **** 
   * 调用SM2密钥对，进行TLS握手，此示例为单项验证 
*/ 
static PKI_CM_Cert_Type test_name2type(const char *type)
{
    if(strcmp(type,"sm2") == 0)
      return CM_CERT_SM2;
    else if(strcmp(type,"rsa") == 0 )
      return CM_CERT_RSA;
    else if(strcmp(type,"secp256r1") == 0 
        || strcmp(type,"secp384r1") == 0
        || strcmp(type,"secp521r1") == 0 
    ) {
      return CM_CERT_ECC;
    } 
    else {
      return CM_CERT_NONE;
    }  
}
#endif
static void dump_x509crt(X509CRT_PCTX x) {
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

static const char *test_convertname(const char *type)
{
    if(strcmp(type,"sm2") == 0)
      return "sm2";
    else if(strcmp(type,"rsa") == 0 )
      return "rsa";
    else if(strcmp(type,"secp256r1") == 0 
        || strcmp(type,"secp384r1") == 0
        || strcmp(type,"secp521r1") == 0 
    ) {
      return "ecc";
    } 
    else {
      return "none";
    }  
}
 
struct MemoryStruct {
  unsigned char *memory;
  size_t size;
};

static unsigned char *hextobin(const char *hex, size_t *olen)
{
  unsigned char *ret = NULL;
  const char *p = NULL;
  size_t hlen = 0;
  int i = 0;

  if(!hex || !olen)
    return NULL;

  hlen = strlen(hex);
  if(hlen % 2)
    return NULL;

  *olen = hlen / 2;

  ret = calloc(1, *olen);
  if(!ret)
    return NULL;

  p = (const char *)hex;
  for ( i = 0; i < *olen; i++ ) 
  {
    sscanf(p, "%2hhx", &ret[i]);
    p += 2;
  }

  return ret;
}

static unsigned char *test_encode_pkcsreq(const char *keytype, const char *sn_in, const unsigned char *deviceid, size_t dlen, size_t *olen)
{
    PKEY_PCTX local_pctx = NULL;
    X509REQ_PCTX x509req = NULL;
    X509CRT_PCTX selfcrt = NULL;
    X509CRT_PCTX scepsvr_crt = NULL;
    char path[256] = {0};
    unsigned char *req_pem = NULL, *req_der = NULL, *privatekey_pem = NULL;
    size_t plen = 0, rlen = 0, prikeypemlen = 0;
    SCEP_REQUEST_PCTX req = NULL; 
    const char *default_sn= "CN=2016120202_VIN_LSGBL5334HF000020,OU=China,O=PKICM", *sn = NULL;
    int ok = 0;
    int ret = 0;
    const char *type = "sm2";
    const char *devid = "DQ5260C150107327";

    if(keytype)
      type = keytype;

    if(sn_in)
      sn = sn_in;
    else
      sn = default_sn;

    memset(path, 0, sizeof(path));
    snprintf(path, sizeof(path), "./kpool/%s.ssl.pvk.pem", type);
    if( strcmp(type, "rsa") == 0 ){
      local_pctx = test_pkey_custom_gen_rsa(path);
      s_assert((local_pctx != NULL), "failure to generate rsa \n");
    }else if( strcmp(type, "sm2") == 0 ){
      local_pctx = test_pkey_custom_gen_sm2(path);
      s_assert((local_pctx != NULL), "failure to generate sm2 \n");
    }else if (strcmp(type, "secp256r1") == 0 
        || strcmp(type,"secp384r1") == 0
        || strcmp(type,"secp512r1") == 0 ){
      local_pctx = test_pkey_custom_gen_ecc("./kpool/ecc.ssl.pvk.pem");
      s_assert((local_pctx != NULL), "failure to generate ecc \n");
    }else {
      printf("invalid type (%s)\n", type);
      return NULL;
    }

    if(keytype)
      type = test_convertname(keytype);

    s_assert((local_pctx != NULL), "failure to generate %s \n", keytype);
    if(!local_pctx)
      goto err;

    memset(path, 0, sizeof(path));
    snprintf(path, sizeof(path), "./kpool/%s.scep.scepsvr.pem", type);
    scepsvr_crt = FILE_getcrt(path);
    s_assert((scepsvr_crt != NULL), "load certificate %s\n error", path); 
    if(!scepsvr_crt)
      goto err;

    ret = cysec_pkey_export_privatekey(local_pctx, &privatekey_pem, &prikeypemlen, PEM);
    s_assert((ret == 0), "export private key error(%08X).\n", ret);
    if(ret) {
      printf("export private key failed.(%08x)\n", ret);
    }

    x509req = cysec_x509req_new(local_pctx);
    s_assert((x509req!=NULL),"generate x509req error...\n"); 
    if(!x509req)
      goto err;

    ret = cysec_x509req_set_subject_name(x509req, sn);
    s_assert((ret==0),"x509req set subject name error ...%08X\n",ret);
    if(ret)
      goto err;

    ret = cysec_x509req_set_serialnumber(x509req,"00:01:02:03");
    s_assert((ret == 0), "x509req set serialnumber error...%08x\n",ret);
    if(ret)
      goto err;

    if(deviceid && dlen)
      ret = cysec_x509req_set_altname(x509req,(const unsigned char *)deviceid,dlen);
    else
      ret = cysec_x509req_set_altname(x509req,(const unsigned char *)devid,strlen(devid));
    s_assert((ret == 0), "set altname ,error = %08X\n", ret);
    if(ret)
      goto err;

    ret = cysec_x509req_set_challengepw(x509req, "password");
    s_assert((ret == 0),"x509req st challenge pw error...%08x\n",ret);
    if(ret)
      goto err;

    ret = cysec_x509req_enable_skid(x509req);
    s_assert((ret == 0), "x509req enable skid error...%08x\n",ret);
    if(ret)
      goto err;

    ret = cysec_x509req_sign(x509req);
    s_assert((ret == 0), "x509req signature error...%08x\n",ret);
    if(ret)
      goto err;

    ret = cysec_x509req_export(x509req, &req_pem, &plen, PEM);
    s_assert((ret == 0), "export x509req pem error ....%08x\n",ret);
    if(ret)
      goto err;

    printf("the  csr is (%s)\n",(char *)req_pem);

    memset(path, 0, sizeof(path));
    snprintf(path, sizeof(path), "./kpool/%s.scep.req.pem", type);    
    ret = FILE_putcontent(req_pem, plen, path);
    /** scep */

    selfcrt =cysec_x509req_to_x509(x509req);
    s_assert((selfcrt!=NULL),"generate selfcert error .\n");
    if(!selfcrt)
      goto err;
    snprintf(path, sizeof(path), "./kpool/%s.scep.selfsign.crt.pem", type);   
    ret = FILE_putcontent((const unsigned char *)cysec_x509crt_as_pem(selfcrt), strlen(cysec_x509crt_as_pem(selfcrt)), path);

    req = cysec_scep_request_pkcsreq_new(x509req, selfcrt, local_pctx, envelop ? scepsvr_crt : NULL);
    s_assert((req!=NULL),"generate the scep request(pkcsreq) error ..\n");
    if(!req)
      goto err;

    ret = cysec_scep_request_encode(req, &req_der, &rlen);
    s_assert((ret == 0), "scep encode error ..ret(%08X)\n",ret);
    if(ret)
      goto err;

    snprintf(path, sizeof(path), "./kpool/%s.scep.pkcsreq.der", type);
    ret = FILE_putcontent( req_der, rlen, path);

    *olen = rlen;
    ok = 1;
err:
    if(req)
      cysec_scep_request_free(req);
    SAFE_FREE(req_pem);
    SAFE_FREE(privatekey_pem);
    if(local_pctx)
      cysec_pkey_free(local_pctx);
    if(selfcrt)
      cysec_x509crt_free(selfcrt);
    if(scepsvr_crt)
      cysec_x509crt_free(scepsvr_crt);
    if(x509req)
      cysec_x509req_free(x509req);

    if(!ok)
      SAFE_FREE(req_der);
    return req_der;
}

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

static int test_decode_certrep(const char *keytype, const unsigned char *in, size_t ilen)
{
    PKEY_PCTX local_pctx = NULL;
    X509CRT_PCTX local_crt = NULL;
    char path[256] = {0};
    unsigned char *pem = NULL, *req_der = NULL;
    SCEP_RESPONSE_PCTX rsp = NULL;
    unsigned char *rsp_der = NULL;
    size_t rsp_dlen = 0;
    X509CRT_PCTX issuedcert = NULL; 
    CERTMGR_PCTX cm = NULL;
    X509CRT_PCTX cacert= NULL;
    int ret = 0;
    unsigned char *cacert_content = NULL;
    size_t cacertlen = 0;
    const char *type = "sm2";

    if(keytype)
      type = keytype;

    if(envelop) {
      memset(path, 0, sizeof(path));
      snprintf(path, sizeof(path), "./kpool/%s.ssl.pvk.pem", type);
      if( strcmp(type, "rsa") == 0 ){
        local_pctx = test_pkey_custom_gen_rsa(path);
        s_assert((local_pctx != NULL), "failure to generate rsa \n");
      }else if( strcmp(type, "sm2") == 0 ){
        local_pctx = test_pkey_custom_gen_sm2(path);
        s_assert((local_pctx != NULL), "failure to generate sm2 \n");
      }else if (strcmp(type, "secp256r1") == 0 
          || strcmp(type,"secp384r1") == 0
          || strcmp(type,"secp512r1") == 0 ){
        local_pctx = test_pkey_custom_gen_ecc("./kpool/ecc.ssl.pvk.pem");
        s_assert((local_pctx != NULL), "failure to generate ecc \n");
      }else {
        printf("invalid type (%s)\n", type);
        return -1;
      }      
    }


#ifndef DO_NOT_USE_PKI_CM_CALLBACK
    ret = PKI_CertManager_get_cacert(test_name2type(type), &cacert_content, &cacertlen);
    if(ret){
      fprintf(stderr,"Get Internal CACERT failed.\n");
      goto err;
    }
#else
    memset(path,0,sizeof(path));
    snprintf(path, sizeof(path),"./kpool/%s.ca.crt.pem",type);
    cacert_content = FILE_getcontent(path, &cacertlen);
    if(!cacert_content){
      fprintf(stderr,"Get Internal CACERT failed.\n");
      goto err;      
    }
#endif

    if(keytype)
      type = test_convertname(keytype);

    cacert = cysec_x509crt_load(cacert_content, cacertlen);
    if(!cacert){
      fprintf(stderr,"the cacert invalid.\n");
      free(cacert_content);
      goto err;
    }
    free(cacert_content);

    memset(path, 0, sizeof(path));
    snprintf(path, sizeof(path), "./kpool/%s.scep.selfsign.crt.pem",type);
    local_crt = FILE_getcrt(path);
    s_assert((local_crt != NULL), "load local certificate %s\n error", path);
    if(!local_crt)
      goto err;


    cm = certmgr_new();
    if(!cm)
      goto err;
    if(cacert){
      ret = certmgr_add_ca(cm, cacert);
      s_assert((ret == 0), "ret=%d\n", ret);
      if(ret)
        goto err;
    }

    memset(path, 0, sizeof(path));
    snprintf(path, sizeof(path), "./kpool/%s.scep.certrep.der", type);    
    rsp_der = FILE_getcontent(path, &rsp_dlen);
    if(!rsp_der)
      goto err;

    rsp = cysec_scep_response_certrep_new(local_crt, envelop ? local_pctx : NULL);
    s_assert("rsp!=NULL", "generate the scep response error ..\n");
    if(!rsp)
      goto err;

    ret = cysec_scep_response_set_verifysigner_callback(rsp, scep_verifysigner_cb, (void *)cm);
    s_assert((ret == 0), "set verifysigner error \n");
    if(ret)
      goto err;

    ret = cysec_scep_response_decode(rsp_der, rsp_dlen, rsp);
    s_assert((ret == 0), "decode scep message error (%08X)", ret);
    if(ret)
      goto err;

    ret = cysec_scep_response_get_messagetype(rsp);
    s_assert((ret == 3), "the messagetype(%d) is not expected",ret);
    if(ret!=3)
      goto err;

    ret = cysec_scep_response_get_pkistatus(rsp);
    s_assert((ret == 0), "the pkistatus is (%d)\n", ret);
    if(ret != 0) {
      ret = cysec_scep_response_get_failinfo(rsp);
      printf("the failinfo is %d\n", ret);
      goto err;
    }

    issuedcert = cysec_scep_response_certrep_get_issuedcert(rsp);
    s_assert((issuedcert!=NULL),"fail to get issued certificate\n");


    if(issuedcert){
      printf("===================GetCert===========================\n");
      dump_x509crt(issuedcert);
      memset(path, 0, sizeof(path));
      snprintf(path, sizeof(path), "./kpool/%s.scep.crt.pem", type);
      ret = FILE_putcontent((const unsigned char *)cysec_x509crt_as_pem(issuedcert), strlen(cysec_x509crt_as_pem(issuedcert)), path);
      if(ret)
        goto err;
      printf("===================success===========================\n");
    }

err:
    if(cm)
      certmgr_free(cm);
    if(issuedcert)
      cysec_x509crt_free(issuedcert);
    if(rsp)
      cysec_scep_response_free(rsp);
    SAFE_FREE(rsp_der);
    SAFE_FREE(req_der);
    SAFE_FREE(pem);
    if(local_pctx)
      cysec_pkey_free(local_pctx);
    if(local_crt)
      cysec_x509crt_free(local_crt);
    if(cacert)
      cysec_x509crt_free(cacert); 
    return 0; 
}

static const char b64_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

char *
test_base64_encode (const unsigned char *src, size_t len) {
  int i = 0;
  int j = 0;
  char *enc = NULL;
  size_t size = 0;
  unsigned char buf[4];
  unsigned char tmp[3];

  // alloc
  enc = (char *) malloc(0);
  if (NULL == enc) { return NULL; }

  // parse until end of source
  while (len--) {
    // read up to 3 bytes at a time into `tmp'
    tmp[i++] = *(src++);

    // if 3 bytes read then encode into `buf'
    if (3 == i) {
      buf[0] = (tmp[0] & 0xfc) >> 2;
      buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
      buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
      buf[3] = tmp[2] & 0x3f;

      // allocate 4 new byts for `enc` and
      // then translate each encoded buffer
      // part by index from the base 64 index table
      // into `enc' unsigned char array
      enc = (char *) realloc(enc, size + 4);
      for (i = 0; i < 4; ++i) {
        enc[size++] = b64_table[buf[i]];
      }

      // reset index
      i = 0;
    }
  }

  // remainder
  if (i > 0) {
    // fill `tmp' with `\0' at most 3 times
    for (j = i; j < 3; ++j) {
      tmp[j] = '\0';
    }

    // perform same codec as above
    buf[0] = (tmp[0] & 0xfc) >> 2;
    buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
    buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
    buf[3] = tmp[2] & 0x3f;

    // perform same write to `enc` with new allocation
    for (j = 0; (j < i + 1); ++j) {
      enc = (char *) realloc(enc, size + 1);
      enc[size++] = b64_table[buf[j]];
    }

    // while there is still a remainder
    // append `=' to `enc'
    while ((i++ < 3)) {
      enc = (char *) realloc(enc, size + 1);
      enc[size++] = '=';
    }
  }

  // Make sure we have enough space to add '\0' character at end.
  enc = (char *) realloc(enc, size + 1);
  enc[size] = '\0';

  return enc;
}


static char *test_urlencode(const unsigned char *in, size_t ilen)
{
  CURL *curl;
  char *ret = NULL;

  curl=curl_easy_init();
  if(!curl)
    return NULL;

  ret = curl_easy_escape(curl, (const char *)in, ilen);
  curl_easy_cleanup(curl);
  return ret;
}

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
  unsigned char *tmpp = NULL;
 
  tmpp = realloc(mem->memory, mem->size + realsize + 1);
  if(tmpp == NULL) {
    /* out of memory! */ 
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = tmpp;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

static int test_httpget(const char *keytype, const char *url, struct MemoryStruct *chunk)
{
  CURL *curl = NULL;
  CURLcode res;
  char errbuf[CURL_ERROR_SIZE]={0};
  const char *type = "sm2";

  type = test_convertname(keytype);
 
  chunk->memory = malloc(1);  /* will be grown as needed by the realloc above */ 
  if(!chunk->memory)
    return -1;
  chunk->size = 0;    /* no data at this point */ 

  curl = curl_easy_init();
  if(curl) {
    /* what call to write: */ 
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connecttimeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunk);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    do { 
      /* 如果需要验证证书链就设置CA证书（CURLOPT_CAINFO）,如果需要调用RSA密钥，就设置"rsa",
       * 如果要调用SM2密钥,就设置为"sm2"，如果要调用ECC密钥，就设置为"ecc" 
       * libcurl 内部会通过接口设置CA证书 ,本例中使用SM2*/
      /**
       * 如果设置 CURLOPT_SSL_VERIFYPEER 为0, 此选项无效 */
#ifndef DO_NOT_USE_PKI_CM_CALLBACK
      curl_easy_setopt(curl, CURLOPT_CAINFO, type);
#else
      char path[256]={0};
      snprintf(path,256,"./kpool/%s.ca.crt.pem",type);
      curl_easy_setopt(curl, CURLOPT_CAINFO, path);
#endif

      /**
       * 如果需要验证服务端证书状态(OCSP Stapling), 则设置CURLOPT_SSL_VERIFYSTATUS 为1 */
      /**
       * 如果设置 CURLOPT_SSL_VERIFYPEER 为0, 此选项无效 */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);

      /**
       * 设置SSL版本
       */
      curl_easy_setopt(curl, CURLOPT_SSLVERSION, ver);

      /**
       * 验证服务端证书主机名 */
      /**
       * 如果设置 CURLOPT_SSL_VERIFYPEER 为0, 此选项无效 */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);


      /* 验证服务端主机，验证为1，不验证为0 */ 
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
 

      /** 不使用信号量，在多线程中如果设置超时，超时使用的是线程不安全的信号机制，所以去掉信号 */
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL , 1L);

      /** 不使用环境变量中的代理 */
      curl_easy_setopt(curl, CURLOPT_PROXY, "");

      /* provide a buffer to store errors in */
      curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

      if(verbose) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, demo_trace);
        curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &config);
      }

      /* Perform the request, res will get the return code */ 
      res = curl_easy_perform(curl);
      /* Check for errors */ 
      if(res != CURLE_OK){
        size_t len = strlen(errbuf);
        time_t t;

        time(&t);
        fprintf(stderr, "\n(%s) ",ctime(&t));
        fprintf(stderr, "libcurl: (%d) ", res);
        if(len)
          fprintf(stderr, "%s%s", errbuf,
                  ((errbuf[len - 1] != '\n') ? "\n" : ""));
        else
          fprintf(stderr, "%s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
      }
 
      /* we are done... */ 
    } while(0);
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
 
  return 0;
}

static int usage(void)
{
  printf(" The SCEP protocol testing.\n");
  printf("--url the SCEP URL (like:https://192.168.10.130:445/sgmx_sm2/pkiclient.exe)\n");
  printf("--keytype like('sm2','rsa','secp256r1','secp384r1','secp521r1')\n");
  printf("--connecttimeout the connect timeout (sec), default 3 sec\n");
  printf("--timeout the operation timeout. default 5 sec\n");
  printf("--debugfile if set -v, you can set a debug file, or output to stderr.\n");
  printf("--debugascii if set -v , you can set the debug print format use ascii.(default print hex)\n");  
  printf("--dn the DN of CSR, like(CN=2016120202_VIN_LSGBL5334HF000020,OU=China,O=PKICM)\n");
  printf("--version tls1.2 or cncav1.1\n");
  printf("--help print this message.\n");
  printf("--altname set subjectaltname by hexstring.(0102030405).\n");
  printf("--unenvelop the SCEP message does't use enveloped pkcs7.\n");
  printf("-v Enable verbose.\n");
  exit(-1);
}

int main(int argc, char ** argv)
{
  const char *url = NULL;
  const char *default_url = "https://192.168.10.130:445/sgmx_sm2/pkiclient.exe";
  unsigned char *req_der = NULL;
  size_t req_der_len = 0;
  char *req_der_base64 = NULL;
  char data[10000] = {0}, path[256]={0};
  int ret = 0;
  char *urldata = NULL;
  struct MemoryStruct chunk;
  unsigned char *cacert_content = NULL;
  size_t cacertlen = 0;
  const char *getcacert_command = "?operation=GetCACert";
  const char *getcert_command = "?operation=PKIOperation&message=";
  X509CRT_PCTX cacert = NULL;
  const char *keytype = "sm2", *dn = NULL,*altname_hex = NULL;
  unsigned char *altname = NULL;
  size_t altnamelen = 0;

  argc--;
  argv++;

  while(argc > 0){
    if(strcmp(*argv,"--url") == 0){
      if(--argc<1)
        break;
      url = *(++argv);
    } else if(strcmp(*argv, "--keytype") == 0 ){
      if(--argc < 1)
        break;
      keytype = *(++argv);
    } else if(strcmp(*argv, "--help") == 0 ){
      usage();
    } else if(strcmp(*argv,"--dn") == 0 ){
      if(--argc < 1)
        break;
      dn = *(++argv);
    } else if(strcmp(*argv, "-v") == 0 ) {
      verbose = 1;
    } else if(strcmp(*argv, "--connecttimeout") == 0 ){
      if(--argc<1)
        break;
      connecttimeout = atol(*(++argv));
    } else if(strcmp(*argv, "--timeout") == 0 ) {
      if(--argc<1)
        break;
      timeout = atoi(*(++argv));
    } else if(strcmp(*argv, "--debugfile") == 0 ) {
      if(--argc<1)
        break;
      debugfile = *(++argv);
    } else if(strcmp(*argv, "--debugascii") == 0 ) {
      debugascii = 1;
    } else if(strcmp(*argv, "--version") == 0 ) {
      if(--argc<1)
        break;
      version = *(++argv);

      if(strcmp(version, "tls1.2") == 0)
      {
        ver = CURL_SSLVERSION_TLSv1_2;
      }
#ifndef DOT_USE_TLS_CNCAV1_1
      else if(strcmp(version, "cncav1.1") == 0)
      {
        ver = CURL_SSLVERSION_CNCAv1_1;
      } 
#endif
      else 
      {
        printf("unsupport ssl protocol %s.\n", version);
        usage();
      }
    }else if(strcmp(*argv,"--altname") == 0 ){
      if(--argc < 1)
        break;
      altname_hex = *(++argv);
    } else if(strcmp(*argv, "--unenvelop") == 0) {
      envelop = 0;
    }
    else
      break;
    argc--;
    argv++;
  }

  if(debugfile) {
    config.stream = fopen(debugfile,"a+");
    if(!config.stream){
      printf("failed to open %s\n", debugfile);
      return 0;
    }
  } else {
    config.stream = NULL;
  }
  config.trace_ascii = (debugascii) ? 1:0;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  if(!url)
    url = default_url;

#ifndef DO_NOT_USE_PKI_CM_CALLBACK
  ret = PKI_CertManager_get_cacert(test_name2type(keytype), &cacert_content, &cacertlen);
  if(ret){
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    fprintf(stderr,"Get Internal CACERT failed.\n");
    exit(8);
  }
#else
  memset(path,0, sizeof(path));
  snprintf(path, sizeof(path),"./kpool/%s.ca.crt.pem",keytype);
  cacert_content = FILE_getcontent(path, &cacertlen);
  if(!cacert_content){
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    fprintf(stderr,"GeInternal CACERT failed.\n");
    exit(8);
  }
#endif

  cacert = cysec_x509crt_load(cacert_content, cacertlen);
  if(!cacert){
    fprintf(stderr,"the cacert invalid.\n");
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    free(cacert_content);
    exit(9);
  }

  dump_x509crt(cacert);
  fprintf(stderr, "got cacert is (%s)\n",cysec_x509crt_as_pem(cacert));
  free(cacert_content);
  cysec_x509crt_free(cacert);

  snprintf(data, sizeof(data), "%s", url);
  snprintf(data+strlen(url), sizeof(data)-strlen(url),"%s", getcacert_command);

  printf("the GetSCEPCert from (%s)\n",data);
  ret = test_httpget(keytype, data, &chunk);
  if(ret){
    printf("get ca cert failed.\n");
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    free(chunk.memory);
    exit(7);
  }

  printf("Got SCEP cert .");
  snprintf(data, sizeof(data), "./kpool/%s.scep.scepsvr.pem", test_convertname(keytype) );
  ret = FILE_putcontent(chunk.memory, chunk.size, data);
  if(ret){
    printf("write scep server certificate error");
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    free(chunk.memory);
    exit(8);
  }
  free(chunk.memory);
  memset(data, 0, sizeof(data));

  if(altname_hex) {
    altname = hextobin(altname_hex, &altnamelen);
    if(!altname) {
      printf("invalid altname %s\n", altname_hex);
      if(debugfile && config.stream){
        fclose(config.stream);
      }
      curl_global_cleanup();
      exit(1);
    }    
  }

  req_der = test_encode_pkcsreq(keytype, dn, altname, altnamelen, &req_der_len);
  if(!req_der){
    free(altname);
    printf("generate pkcsreq failed.\n");
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    curl_global_cleanup();
    exit(1);
  }
  free(altname);

  req_der_base64 = test_base64_encode(req_der, req_der_len);
  if(ret != 0 ){
    printf("base64 failed.\n");
    free(req_der);
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    curl_global_cleanup();
    exit(2);
  }

  urldata = test_urlencode((const unsigned char *)req_der_base64, strlen(req_der_base64));
  if(!urldata){
    printf("urlencode failed.\n");
    free(req_der);
    free(req_der_base64);
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    curl_global_cleanup();
    exit(3);
  }

  snprintf(data, sizeof(data), "%s", url);
  snprintf(data + strlen(url), sizeof(data) - strlen(url), "%s", getcert_command);
  snprintf(data + strlen(url) + strlen(getcert_command), sizeof(data) - strlen(url) -strlen(getcert_command), "%s", urldata);
  printf("url (%s)\n",data);

  free(urldata);
  free(req_der_base64);
  free(req_der);

  printf("Send SCEP request.\n");
  ret = test_httpget(keytype, data,&chunk);
  if(ret){
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    curl_global_cleanup();
    exit(4);
  }

  printf("Got SCEP response.\n");
  memset(data, 0, sizeof(data));
  snprintf(data, sizeof(data), "./kpool/%s.scep.certrep.der", test_convertname(keytype));
  ret = FILE_putcontent(chunk.memory, chunk.size, data);
  if(ret){
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    curl_global_cleanup();
    printf("the sm2.scep.certrep.der failed.\n");
    exit(6);
  }
  ret = test_decode_certrep(keytype, (const unsigned char *)chunk.memory, chunk.size);
  if(ret){
    if(debugfile && config.stream){
      fclose(config.stream);
    }
    curl_global_cleanup();
    exit(5);
  }

  if(debugfile && config.stream){
    fclose(config.stream);
  }
  free(chunk.memory);
  curl_global_cleanup();
  exit(0);
}
#endif /* HAVE_PK_CUSTOM_SUPPORT */
