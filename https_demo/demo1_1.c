/**
 * shows https usage with Curl(Base on CysecSDK).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include <curl/curl.h>
#include "util.h"

#define ROOTCA_CRT_PATH            "./kpool/%s.rootca.crt.pem"
#define CA_CRT_PATH                "./kpool/%s.ca.crt.pem"
#define SELFSIGN_PVK_PATH          "./kpool/%s.selfsign.pvk.pem"
#define SIGN_CRT_PATH               "./kpool/%s.sign.crt.pem"
#define SIGN_PVK_PATH              SELFSIGN_PVK_PATH     
#define ENC_CRT_PATH              "./kpool/%s.enc.crt.pem"
#define ENC_PVK_PATH              "./kpool/%s.enc.pvk.pem"
#define CA_PATH                   "./kpool"

#define set_path(p, type) do{ \
  memset(path, 0, sizeof(path)); \
  snprintf(path, sizeof(path), p, type); \
}while(0)

static int usage(void)
{
  printf(" TLS client/server both verify without callback.\n");
  printf("--url the https URL (like:https://192.168.10.130:445)\n");
  printf("--keytype like('sm2','rsa','secp256r1','secp384r1','secp521r1')\n");
  printf("--connecttimeout the connect timeout (sec), default 3 sec\n");
  printf("--timeout the operation timeout. default 5 sec\n");
  printf("--debugfile if set -v, you can set a debug file, or output to stderr.\n");
  printf("--debugascii if set -v , you can set the debug print format use ascii.(default print hex)\n");
  printf("--forbid_reuse_socket forbid reuse socket.\n");
  printf("--version tls1.2 or cncav1.1\n");
  printf("--help print this message.\n");
  printf("--capath use the capath for verify. default use cafile.\n");
  printf("-v Enable verbose.\n");
  exit(-1);
}

/* 
   **** This example only works with libcurl base on CysecSDK  **** 
   * 调用SM2密钥对，进行TLS握手，此示例为双向验证 
*/ 
 
int main(int argc, char ** argv)
{
  CURL *curl;
  CURLcode res;
  const char *default_url="https://192.168.10.130:446";
  const char *url = NULL;
  char errbuf[CURL_ERROR_SIZE]={0};
  char path[256] = {0};
  const char *keytype = NULL, *type = "sm2";
  long verbose = 0;
  long connecttimeout = 3L;
  long timeout = 5L;
  const char *debugfile = NULL;
  struct trace_data config;
  int debugascii = 0;
  const char *version = NULL;
  long ver = CURL_SSLVERSION_TLSv1_2;
  int capath = 0;

  argc--;
  argv++;

  while(argc > 0){
    if(strcmp(*argv,"--url") == 0){
      if(--argc<1)
        break;
      url = *(++argv);
    }else if(strcmp(*argv, "--keytype") == 0 ){
      if(--argc < 1)
        break;
      keytype = *(++argv);
    } else if(strcmp(*argv, "--help") == 0 ){
      usage();
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
    } else if(strcmp(*argv, "--capath") == 0 ) {
      capath = 1;
    }else if(strcmp(*argv, "--version") == 0 ) {
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
    }
    else{
      printf("unsupport option %s.\n", *argv);
      usage();
    }

    argc--;
    argv++;
  }

  if(!url)
    url = default_url;

  if(keytype){
    if(strcmp(keytype,"rsa") == 0 || strcmp(keytype,"sm2") == 0 )
      type = keytype;
    else if(strcmp(keytype, "secp256r1") == 0 
          || strcmp(keytype, "secp384r1") == 0
          || strcmp(keytype, "secp521r1") == 0
          )
      type = "ecc";
    else
      type = "none";
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
  curl = curl_easy_init();
  if(curl) {
    /* what call to write: */ 
    curl_easy_setopt(curl, CURLOPT_URL, url);
 
    do { 
#ifndef DOT_USE_TLS_CNCAV1_1
      if(ver == CURL_SSLVERSION_CNCAv1_1) {

        curl_easy_setopt(curl, CURLOPT_SSLENCCERTTYPE, "PEM");

        set_path(ENC_CRT_PATH, type);
        curl_easy_setopt(curl, CURLOPT_SSLENCCERT, path);
        

        curl_easy_setopt(curl, CURLOPT_SSLENCKEYTYPE, "PEM");
   
        set_path(ENC_PVK_PATH, type);
        curl_easy_setopt(curl, CURLOPT_SSLENCKEY, path);        
      }
#endif

      if(capath) 
        curl_easy_setopt(curl, CURLOPT_CAPATH, CA_PATH);
      else {
        set_path(CA_CRT_PATH, type);
        curl_easy_setopt(curl, CURLOPT_CAINFO, path);
      }

      /**
       * 如果需要验证服务端证书状态(OCSP Stapling), 则设置CURLOPT_SSL_VERIFYSTATUS 为1 */
      /**
       * 如果设置 CURLOPT_SSL_VERIFYPEER 为0, 此选项无效 */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1);

      /**
       * 验证服务端证书主机名 */
      /**
       * 如果设置 CURLOPT_SSL_VERIFYPEER 为0, 此选项无效 */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);

      /**
       * 设置SSL版本
       */
      curl_easy_setopt(curl, CURLOPT_SSLVERSION, ver);

      curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
 
      set_path(SIGN_CRT_PATH, type);
      curl_easy_setopt(curl, CURLOPT_SSLCERT, path);
      
      /** 不读取环境变量proxy */
      curl_easy_setopt(curl, CURLOPT_PROXY, "");
 
      curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
 
      set_path(SIGN_PVK_PATH, type);
      curl_easy_setopt(curl, CURLOPT_SSLKEY, path);
 
       /** 设置DNS，connect timeout */
      curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connecttimeout);
      
      /** 设置超时 */
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

      /** 不使用信号量，在多线程中如果设置超时，超时使用的是线程不安全的信号机制，所以去掉信号 */
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL , 1L);

      /** 不使用环境变量中的代理 */
      curl_easy_setopt(curl, CURLOPT_PROXY, "");

      /* 验证服务端主机 */ 
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
 
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
 
  curl_global_cleanup();
   if(debugfile && config.stream){
    fclose(config.stream);
  }

  return 0;
}