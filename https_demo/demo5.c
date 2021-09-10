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
#include "util.h"
 
long verbose = 0;
long timeout = 10L;
long connecttimeout = 5L;
const char *debugfile = NULL;
struct trace_data config;
int debugascii = 0;
const char *version = NULL;
long ver = CURL_SSLVERSION_TLSv1_2;
int envelop = 0;

#define SCEP_SERVER_CRT_PATH       "./kpool/%s.scepsvr.crt.pem"
#define ROOTCA_CRT_PATH            "./kpool/%s.rootca.crt.pem"
#define CA_CRT_PATH                "./kpool/%s.ca.crt.pem"
#define CSR_PATH                   "./kpool/%s.csr.pem"
#define SELFSIGN_PVK_PATH          "./kpool/%s.selfsign.pvk.pem"
#define SELFSIGN_CRT_PATH          "./kpool/%s.selfsign.crt.pem"
#define SIGN_CRT_PATH               "./kpool/%s.sign.crt.pem"
#define SIGN_PVK_PATH SELFSIGN_PVK_PATH     
#define ENC_CRT_PATH              "./kpool/%s.enc.crt.pem"
#define ENC_PVK_PATH              "./kpool/%s.enc.pvk.pem"
#define SCEP_REQUEST_PATH         "./kpool/%s.scep.request.der"
#define SCEP_RESPONSE_PATH         "./kpool/%s.scep.response.der"
#define RENEW_SELFSIGN_PVK_PATH   "./kpool/%s.renew.selfsign.pvk.pem"
#define RENEW_SELFSIGN_CRT_PATH   "./kpool/%s.renew.selfsign.crt.pem"
#define RENEW_CSR_PATH            "./kpool/%s.renew.csr.pem"
#define RENEW_SIGN_CRT_PATH               "./kpool/%s.renew.sign.crt.pem"
#define RENEW_SIGN_PVK_PATH RENEW_SELFSIGN_PVK_PATH     
#define RENEW_ENC_CRT_PATH              "./kpool/%s.renew.enc.crt.pem"
#define RENEW_ENC_PVK_PATH              "./kpool/%s.renew.enc.pvk.pem"
#define RENEW_SCEP_REQUEST_PATH         "./kpool/%s.renew.scep.request.der"
#define RENEW_SCEP_RESPONSE_PATH        "./kpool/%s.renew.scep.response.der"

#define set_path(p, type) do{ \
  memset(path, 0, sizeof(path)); \
  snprintf(path, sizeof(path), p, type); \
}while(0)

#ifndef DO_NOT_USE_PKI_CM_CALLBACK
/* 名字转化成枚举值 */
static PKI_CM_Cert_Type test_name2type(const char *type)
{
    if(strcmp(type,"sm2") == 0)
      return CM_CERT_SM2;
    else if(strcmp(type,"rsa") == 0 )
      return CM_CERT_RSA;
    else if(strcmp(type,"secp256r1") == 0 
        || strcmp(type,"secp384r1") == 0
        || strcmp(type,"secp521r1") == 0 
        || strcmp(type,"ecc") == 0
    ) {
      return CM_CERT_ECC;
    } 
    else {
      return CM_CERT_NONE;
    }  
}
#endif

/* 转化成libpkicm支持的"rsa","sm2","ecc" */
static const char *test_convertname(const char *type)
{
    if(strcmp(type,"sm2") == 0)
      return "sm2";
    else if(strcmp(type,"rsa") == 0 )
      return "rsa";
    else if(strcmp(type,"secp256r1") == 0 
        || strcmp(type,"secp384r1") == 0
        || strcmp(type,"secp521r1") == 0 
        || strcmp(type,"ecc") == 0
    ) {
      return "ecc";
    } 
    else {
      return NULL;
    }  
}

/* 名字转化成枚举值 */
static HASH_ALG convertdigest(const char* digest)
{
  if(strcmp(digest, "sm3") == 0)
    return HASH_ALG_SM3;
  else if(strcmp(digest, "sha256") == 0) {
    return HASH_ALG_SHA256;
  } else {
    return HASH_ALG_SM3; //default sm3
  }
}

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
    if(!r)
      return NULL;
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

static int FILE_writecontent(const unsigned char *in, size_t ilen, const char *fname){
  FILE *fp = NULL;
  int ret = 0;

  if ((fp = fopen(fname,"w"))==NULL) {
    return -1;
    } 

    if(in && ilen > 0){
      ret = fwrite(in, 1, ilen, fp);
      if(ret != (int)ilen){
        fclose(fp);
        return -1;
      }
    }

    fclose(fp);
    return 0;
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

int digest_one(const unsigned char *buf, size_t blen, HASH_ALG halg, unsigned char *out, size_t *olen)
{
  DIGEST_PCTX md_ctx;
  size_t mdlen = 0;
  int ret = 0;

  if(!buf || blen == 0 || !out || !olen )
    return CYSEC_E_INVALID_ARG;

  mdlen = cysec_digest_size(halg);
  if(mdlen == 0 || mdlen > *olen )
    return CYSEC_E_INVALID_ARG;

  *olen = mdlen;
  md_ctx = cysec_digest_ctx_new(halg);
  if(!md_ctx)
    return CYSEC_E_MEMORY_E;

  if( (ret = cysec_digest_init(md_ctx, NULL)) != 0 ||
    (ret = cysec_digest_update(md_ctx, buf, blen)) != 0 ||
    (ret = cysec_digest_final(md_ctx, out)) != 0 )
  {
    cysec_digest_ctx_free(md_ctx);
    return ret;
  }

  cysec_digest_ctx_free(md_ctx);
  return 0;
}

static  int test_gen_csr(const char *keytype, const char *sn_in, 
  const unsigned char *deviceid, size_t dlen, int renew,
  X509REQ_PCTX *csr, PKEY_PCTX *pkey)
{
  PKEY_PCTX new_pctx = NULL;
  X509REQ_PCTX x509req = NULL;
  char path[256] = {0};
  unsigned char *req_pem = NULL, *req_der = NULL, *privatekey_pem = NULL;
  size_t plen = 0, rlen = 0, prikeypemlen = 0;
  const char *default_sn= "CN=2016120202_VIN_LSGBL5334HF000020,OU=China,O=PKICM", *sn = NULL;
  int ok = -1;
  int ret = 0;
  const char *type = "sm2";
  const char *devid = "DQ5260C150107327";

  if(!csr || !pkey)
    return -1;

  if(keytype)
    type = keytype;

  if(strcmp(type,"sm2") == 0)
    new_pctx = cysec_pkey_gen_sm2();
  else if(strcmp(type,"rsa") == 0 )
    new_pctx = cysec_pkey_gen_rsa(1024);
  else if(strcmp(type,"secp256r1") == 0 
      || strcmp(type,"secp384r1") == 0
      || strcmp(type,"secp512r1") == 0 
  ) {
    new_pctx = cysec_pkey_gen_ecc_by_name(keytype);
    type = "ecc";
  } 
  else {
    printf("invalid type (%s)\n", type);
    return -1;
  }

  sn = (sn_in) ? sn_in : default_sn;

  if(!new_pctx){
    printf("Failed to generate a %s keypair.\n", keytype);
    goto err;
  }

  ret = cysec_pkey_export_privatekey(new_pctx, &privatekey_pem, &prikeypemlen, PEM);
  if(ret) {
    printf("Failed to export private key  (%08x).\n", ret);
    goto err;
  }

  set_path(renew ? RENEW_SELFSIGN_PVK_PATH : SIGN_PVK_PATH, type);
  ret = FILE_writecontent(privatekey_pem, prikeypemlen, path);
  SAFE_FREE(privatekey_pem);

  x509req = cysec_x509req_new(new_pctx);
  if(!x509req) {
    printf("Failed to generate a CSR.\n");
    goto err;
  }

  ret = cysec_x509req_set_subject_name(x509req, sn);
  if(ret) {
    printf("Failed to set subject name for CSR (%s) %08x\n", sn, ret);
    goto err;
  }

  ret = cysec_x509req_set_serialnumber(x509req,"00:01:02:03");
  if(ret) {
    printf("Failed to set serialnumber 01:02:03:04 error %08x. for CSR\n",ret);
    goto err;
  }

  if(deviceid && dlen)
    ret = cysec_x509req_set_altname(x509req,(const unsigned char *)deviceid,dlen);
  else
    ret = cysec_x509req_set_altname(x509req,(const unsigned char *)devid,strlen(devid));
  if(ret) {
    printf("Failed to set altname error %08x for CSR.",ret);
    goto err;
  }

  ret = cysec_x509req_set_challengepw(x509req, "password");
  if(ret) {
    printf("Failed to set challengepw for CSR, error = %08x\n", ret);
    goto err;
  }

  ret = cysec_x509req_enable_skid(x509req);
  if(ret) {
    printf("failed to enable the SKID for CSR. error = %08x\n.", ret);
    goto err;
  }

  ret = cysec_x509req_sign(x509req);
  if(ret) {
    printf("failed to sign a CSR, error = %08x\n", ret);
    goto err;
  }

  ret = cysec_x509req_export(x509req, &req_pem, &plen, PEM);
  if(ret) {
    printf("Failed to export a CSR. error = %08x.\n", ret);
    goto err;
  }

  printf("the  csr (%s)\n",(char *)req_pem);

  set_path(renew ? RENEW_CSR_PATH : CSR_PATH, type); 
  ret = FILE_writecontent(req_pem, plen, path);
  if(ret){
    printf("Failed to write (%s)", path);
    goto err;
  }

  *csr = x509req;
  *pkey = new_pctx;
  ok = 0;
err:
  if(ok != 0){
    if(x509req){
      cysec_x509req_free(x509req);
      x509req = NULL;
    }
    if(new_pctx){
      cysec_pkey_free(new_pctx);
      new_pctx = NULL;
    }
  }

  return ok;
}

#if 1
static unsigned char *test_encode_renewalreq(const char *keytype, const char *sn_in, 
  const unsigned char *deviceid, size_t dlen, size_t *olen)
{
  PKEY_PCTX new_pctx = NULL;
  X509REQ_PCTX x509req = NULL;
  X509CRT_PCTX old_crt = NULL;
  PKEY_PCTX old_pctx = NULL;
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

  ret = test_gen_csr(keytype, sn_in, deviceid, dlen, 1, &x509req, &new_pctx);
  if(ret){
    printf("Failed to generate CSR.\n");
    goto err;
  }
    if(keytype)
    type = test_convertname(keytype);
    
  set_path(SIGN_CRT_PATH, type);
  old_crt = FILE_getcrt(path);
  if(!old_crt)
    goto err;

  set_path(SIGN_PVK_PATH, type);
  old_pctx = FILE_getpvk(path);
  if(!old_pctx)
    goto err;

  set_path(SCEP_SERVER_CRT_PATH, type);
  scepsvr_crt = FILE_getcrt(path);
  if(!scepsvr_crt){
    printf("Failed to load scep server certificate %s\n.", path);
    goto err;
  }

  req = cysec_scep_request_renewalreq_new(x509req, old_crt, old_pctx, envelop ? scepsvr_crt : NULL);
  if(!req) {
    printf("Failed to generate a scep renewalreq. error %08x.\n", ret);
    goto err;
  }

  ret = cysec_scep_request_encode(req, &req_der, &rlen);
  if(ret) {
    printf("Failed to encode a scep request. error = %08x\n", ret);
    goto err;
  }

  set_path(RENEW_SCEP_REQUEST_PATH, type);
  ret = FILE_writecontent( req_der, rlen, path);

  *olen = rlen;
  ok = 1;
err:
  if(req)
    cysec_scep_request_free(req);
  SAFE_FREE(req_pem);
  SAFE_FREE(privatekey_pem);
  if(new_pctx)
    cysec_pkey_free(new_pctx);
  if(old_pctx)
    cysec_pkey_free(old_pctx);
  if(old_crt)
    cysec_x509crt_free(old_crt);
  if(scepsvr_crt)
    cysec_x509crt_free(scepsvr_crt);
  if(x509req)
    cysec_x509req_free(x509req);

  if(!ok)
    SAFE_FREE(req_der);
  return req_der;
}
#endif

static unsigned char *test_encode_pkcsreq(const char *keytype, const char *sn_in, 
  const unsigned char *deviceid, size_t dlen, size_t *olen)
{
    PKEY_PCTX local_pctx = NULL;
    X509REQ_PCTX x509req = NULL;
    X509CRT_PCTX scepsvr_crt = NULL, selfcrt = NULL;
    char path[256] = {0};
    unsigned char *req_pem = NULL, *req_der = NULL, *privatekey_pem = NULL;
    size_t plen = 0, rlen = 0, prikeypemlen = 0;
    SCEP_REQUEST_PCTX req = NULL; 
    const char *default_sn= "CN=2016120202_VIN_LSGBL5334HF000020,OU=China,O=PKICM", *sn = NULL;
    int ok = 0;
    int ret = 0;
    const char *type = "sm2";
    const char *devid = "DQ5260C150107327";

    ret = test_gen_csr(keytype, sn_in, deviceid, dlen, 0, &x509req, &local_pctx);
    if(ret){
      printf("Failed to generate CSR.\n");
      goto err;
    }

    selfcrt = cysec_x509req_to_x509(x509req);
    if(!selfcrt){
      printf("Failed to generate a selfcert from CSR. \n");
      goto err;
    }

    if(keytype)
      type = test_convertname(keytype);

    set_path(SELFSIGN_CRT_PATH, type);
    ret = FILE_writecontent((const unsigned char *)cysec_x509crt_as_pem(selfcrt), strlen(cysec_x509crt_as_pem(selfcrt)), path);
    if(ret){
      printf("failed to write a selfsign certificate file to %s. ret = %d", path, ret);
      goto err;
    }

    set_path(SCEP_SERVER_CRT_PATH, type);
    scepsvr_crt = FILE_getcrt(path);
    if(!scepsvr_crt){
      printf("Failed to load scep server certificate %s\n.", path);
      goto err;
    }

    req = cysec_scep_request_pkcsreq_new(x509req, selfcrt, local_pctx, envelop ? scepsvr_crt: NULL);
    s_assert((req!=NULL),"generate the scep request(pkcsreq) error ..\n");
    if(!req) {
      printf("Failed to generate a scep request. error = %08x.\n", ret);
      goto err;
    }

    ret = cysec_scep_request_encode(req, &req_der, &rlen);
    if(ret) {
      printf("Failed to encode a scep request. error = %08x\n", ret);
      goto err;
    }

    set_path(SCEP_REQUEST_PATH, type);
    ret = FILE_writecontent( req_der, rlen, path);

    *olen = rlen;
    ok = 1;
err:
    if(req)
      cysec_scep_request_free(req);
    SAFE_FREE(req_pem);
    SAFE_FREE(privatekey_pem);
    if(local_pctx)
      cysec_pkey_free(local_pctx);
    if(scepsvr_crt)
      cysec_x509crt_free(scepsvr_crt);
    if(x509req)
      cysec_x509req_free(x509req);
    if(selfcrt)
      cysec_x509crt_free(selfcrt);

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
    PKEY_PCTX local_pctx = NULL, local_enc_pctx = NULL;
    X509CRT_PCTX local_crt = NULL;
    char path[256] = {0};
    unsigned char *pem = NULL, *req_der = NULL;
    SCEP_RESPONSE_PCTX rsp = NULL;
    unsigned char *rsp_der = NULL;
    size_t rsp_dlen = 0;
    X509CRT_PCTX issuedcert = NULL, issued_enc_cert = NULL; 
    CERTMGR_PCTX cm = NULL;
    X509CRT_PCTX cacert= NULL;
    int ret = 0;
    unsigned char *cacert_content = NULL;
    size_t cacertlen = 0;
    const char *type = "sm2";

    if(keytype)
      type = keytype;

    type = test_convertname(type);

#ifndef DO_NOT_USE_PKI_CM_CALLBACK
    ret = PKI_CertManager_get_cacert(test_name2type(keytype), &cacert_content, &cacertlen);
    if(ret){
      fprintf(stderr,"Failed to get cacert from libpkicm.so.\n");
      goto err;
    }
#else
    memset(path,0,sizeof(path));
    snprintf(path, sizeof(path), CA_CRT_PATH, type);
    cacert_content = FILE_getcontent(path, &cacertlen);
    if(!cacert_content){
      fprintf(stderr,"Failed to get ca certificate from CA_CRT_PATH.\n", type);
      goto err;      
    }
#endif

    cacert = cysec_x509crt_load(cacert_content, cacertlen);
    if(!cacert){
      fprintf(stderr,"the CA certificate is an invalid certificate. (%s)\n", cacert_content);
      free(cacert_content);
      goto err;
    }
    free(cacert_content);

    set_path(SELFSIGN_CRT_PATH, type);
    local_crt = FILE_getcrt(path);
    if(!local_crt){
      fprintf(stderr, "Failed to load local selfsign certificate %s\n", path);
      goto err;
    }

    set_path(SELFSIGN_PVK_PATH, type);
    local_pctx = FILE_getpvk(path);
    if(!local_pctx) {
      fprintf(stderr, "Failed to local local privatekey %s \n", path);
      goto err;
    }   

    cm = certmgr_new();
    if(!cm)
      goto err;
    if(cacert){
      ret = certmgr_add_ca(cm, cacert);
      if(ret)
        goto err;
    }

    set_path(SCEP_RESPONSE_PATH, type);
    rsp_der = FILE_getcontent(path, &rsp_dlen);
    if(!rsp_der){
      printf("Failed to get scep response from %s", path);
      goto err;
    }

    rsp = cysec_scep_response_certrep_new(local_crt, local_pctx);
    if(!rsp) {
      printf("Failed to get scep response ctx.");
      goto err;
    }

    ret = cysec_scep_response_set_verifysigner_callback(rsp, scep_verifysigner_cb, (void *)cm);
    if(ret) {
      goto err;
    }

    ret = cysec_scep_response_decode(rsp_der, rsp_dlen, rsp);
    if(ret) {
      printf("failed to decode scep message. error = %08x\n", ret);
      goto err;
    }

    ret = cysec_scep_response_get_messagetype(rsp);
    if(ret != 3) {
      printf("the messagetype (%d) is not expected.\n", ret);
      goto err;
    }

    ret = cysec_scep_response_get_pkistatus(rsp);
    if(ret != 0) {
      printf("the pkistatus is (%d) not expected.\n", ret);
      ret = cysec_scep_response_get_failinfo(rsp);
      printf("the failinfo is %d\n", ret);
      goto err;
    }

    issuedcert = cysec_scep_response_certrep_get_issuedcert(rsp);
    if(!issuedcert){
      printf("failed to get issuedcert.\n");
      goto err;
    }

    if(issuedcert){
      printf("===================Get Cert===========================\n");
      dumpcrt(issuedcert);
      set_path(SIGN_CRT_PATH, type);
      ret = FILE_writecontent((const unsigned char *)cysec_x509crt_as_pem(issuedcert), strlen(cysec_x509crt_as_pem(issuedcert)), path);
      if(ret)
        goto err;
      printf("===================success===========================\n");
    }

#ifndef DOT_USE_TLS_CNCAV1_1
    issued_enc_cert = cysec_scep_response_certrep_get_issued_enccert(rsp);
    if(issued_enc_cert) {
      printf("===================Get encryption Cert===========================\n");
      dumpcrt(issued_enc_cert);
      set_path(ENC_CRT_PATH, type);
      ret = FILE_writecontent((const unsigned char *)cysec_x509crt_as_pem(issued_enc_cert), strlen(cysec_x509crt_as_pem(issued_enc_cert)), path);
      if(ret)
        goto err;
      printf("===================success===========================\n");
    }

    local_enc_pctx = cysec_scep_response_certrep_get_enc_pvk(rsp);
    if(local_enc_pctx) {
      unsigned char *tmp;
      size_t tlen;

      printf("===================GetEncPvk===========================\n");
      dumpkey(local_enc_pctx);
      printf("===================success===========================\n");

      set_path(ENC_PVK_PATH, type);
      ret = cysec_pkey_export_privatekey(local_enc_pctx, &tmp, &tlen, PEM);
      if(ret){
        goto err;
      }

      ret = FILE_writecontent(tmp, tlen, path);
      if(ret){
        free(tmp);
        goto err;
      }  
      free(tmp);
    }
#endif
err:
    if(cm)
      certmgr_free(cm);
    if(issuedcert)
      cysec_x509crt_free(issuedcert);
#ifndef DOT_USE_TLS_CNCAV1_1
    if(issued_enc_cert)
      cysec_x509crt_free(issued_enc_cert);
    if(local_enc_pctx)
      cysec_pkey_free(local_enc_pctx);
#endif
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
      set_path(CA_CRT_PATH, type);
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
  printf("--altnamehex set subjectaltname by hexstring.(0102030405).\n");
  printf("--altnameplain set subjectaltname by plain string(eg : 'samplesubjectaltname')\n");
  printf("--altnamedigest set subjectaltname digest algorithm('sm3','sha256')\n");
  printf("--envelop the SCEP use envelopd PKCS7. default 0\n");
  printf("--reqtype the request type ( PKCSREQ 1, RENEWALREQ 2) ,default pkcsreq\n");
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
  const char *keytype = "sm2", *dn = NULL,*altname_hex = NULL, *altname_plain = NULL, *altname_digest = NULL;
  unsigned char *altname = NULL;
  size_t altnamelen = 0;
  int reqtype = 1;
  HASH_ALG altname_digest_algo;

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
    } else if(strcmp(*argv,"--altnamehex") == 0 ){
      if(--argc < 1)
        break;
      altname_hex = *(++argv);
    } else if(strcmp(*argv,"--altnameplain") == 0 ){
      if(--argc < 1)
        break;
      altname_plain = *(++argv);
    } else if(strcmp(*argv,"--altnamedigest") == 0 ){
      if(--argc < 1)
        break;
      altname_digest = *(++argv);
    } else if(*argv, "--envelop") {
      envelop = 1;
    } else if(strcmp(*argv, "--reqtype") == 0 ){
      if(--argc <1)
        break;
      reqtype = atoi(*(++argv));
      if(reqtype !=1 && reqtype != 2){
        printf("invalid reqtype (%d)\n", reqtype);
        usage();
      }
    }
    else{
      printf("unsupport option %s.\n", *argv);
      usage();
    }

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
    fprintf(stderr,"Failed to get the CA certificate from libpkicm.\n");
    goto end;
  }
#else
  set_path(CA_CRT_PATH, test_convertname(keytype));
  cacert_content = FILE_getcontent(path, &cacertlen);
  if(!cacert_content){
    fprintf(stderr,"Failed to get the CA certificate from %d.\n", path);
    goto end;
  }
#endif

  cacert = cysec_x509crt_load(cacert_content, cacertlen);
  if(!cacert){
    fprintf(stderr,"The CA ceritificate is an invalid certificate(%s).\n", cacert_content);
    goto end;
  }

  dumpcrt(cacert);
  fprintf(stderr, "got cacert is (%s)\n",cysec_x509crt_as_pem(cacert));

  snprintf(data, sizeof(data), "%s", url);
  snprintf(data + strlen(url), sizeof(data) - strlen(url), "%s", getcacert_command);

  printf("the GetSCEPCert from (%s)\n",data);
  ret = test_httpget(keytype, data, &chunk);
  if(ret){
    printf("Failed to get the scep server certificate.\n");
    free(chunk.memory);
    goto end;
  }

  printf("Got SCEP cert .");
  set_path(SCEP_SERVER_CRT_PATH, test_convertname(keytype));
  ret = FILE_writecontent(chunk.memory, chunk.size, path);
  if(ret){
    printf("Failed to write the scep server certificate to %s .\n", path);
    goto end;
  }
  free(chunk.memory);

  if(altname_hex) {
    printf("use HEX string subjectaltname\n");
    altname = hextobin(altname_hex, &altnamelen);
    if(!altname) {
      printf("invalid altname %s\n", altname_hex);
      goto end;
    }    
  } else if(altname_plain && altname_digest) {
    printf("use plain string subjectaltname\n");
    altname_digest_algo = convertdigest(altname_digest);
    altnamelen = cysec_digest_size(altname_digest_algo);
    altname = calloc(1, altnamelen);
    if(!altname) {
      printf("out of memory\n");
      goto end;
    }

    ret = digest_one(altname_plain, strlen(altname_plain), altname_digest_algo, altname, &altnamelen);
    if(ret) {
      printf("compute subjectaltname digest failed by %s\n", altname_digest);
      goto end;
    }
  }

  if(reqtype == 1) {
    req_der = test_encode_pkcsreq(keytype, dn, altname, altnamelen, &req_der_len);    
  } else if(reqtype == 2) {
    req_der = test_encode_renewalreq(keytype, dn, altname, altnamelen, &req_der_len);
  }
  if(!req_der){
    printf("Failed to generate a SCEP request.\n");
    goto end;
  }

  req_der_base64 = test_base64_encode(req_der, req_der_len);
  if(ret != 0 ){
    printf("base64 failed.\n");
    goto end;
  }

  urldata = test_urlencode((const unsigned char *)req_der_base64, strlen(req_der_base64));
  if(!urldata){
    printf("urlencode failed.\n");
    goto end;
  }

  memset(data, 0, sizeof(data));
  snprintf(data, sizeof(data), "%s", url);
  snprintf(data + strlen(url), sizeof(data) - strlen(url), "%s", getcert_command);
  snprintf(data + strlen(url) + strlen(getcert_command), sizeof(data) - strlen(url) - strlen(getcert_command), "%s", urldata);
  printf("url (%s)\n",data);

  printf("Send SCEP request.\n");
  ret = test_httpget(keytype, data, &chunk);
  if(ret){
    printf("Failed to send a SCEP request. (%08x)\n", ret);
    free(chunk.memory);
    goto end;
  }

  printf("Got SCEP response.\n");
  set_path(SCEP_RESPONSE_PATH, test_convertname(keytype));
  ret = FILE_writecontent(chunk.memory, chunk.size, path);
  if(ret){
    printf("Failed to write SCEP response to %s \n", path);
    goto end;
  }

  ret = test_decode_certrep(keytype, (const unsigned char *)chunk.memory, chunk.size);
  if(ret){
    free(chunk.memory);
    goto end;
  }
  free(chunk.memory);

  ret = 0;
end:
  if(cacert_content)
    free(cacert_content);

  if(cacert)
    cysec_x509crt_free(cacert);

  if(urldata)
    free(urldata);

  if(altname)
    free(altname);

  if(req_der)
    free(req_der);

  if(req_der_base64)
    free(req_der_base64);

  if(debugfile && config.stream){
    fclose(config.stream);
  }
  curl_global_cleanup();

  exit(ret);
}
