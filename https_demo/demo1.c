/**
 * shows https usage with Curl(Base on CysecSDK).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include <curl/curl.h>
#include "util.h"
 
static int usage(void)
{
  printf(" TLS client/server both verify with callback.\n");
  printf("--url the https URL (like:https://192.168.10.130:445)\n");
  printf("--keytype like('sm2','rsa','secp256r1','secp384r1','secp521r1')\n");
  printf("--connecttimeout the connect timeout (sec), default 3 sec\n");
  printf("--timeout the operation timeout. default 5 sec\n");
  printf("--debugfile if set -v, you can set a debug file, or output to stderr.\n");
  printf("--debugascii if set -v , you can set the debug print format use ascii.(default print hex)\n");
  printf("--version tls1.2 or cncav1.1\n");
  printf("--help print this message.\n");
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
  long ip4_ttl = 0, dns_ip4_ttl = 0;
  const char *dns_strings = NULL;
  char errbuf[CURL_ERROR_SIZE]={0};
  const char *type = "sm2", *keytype = NULL;
  long verbose = 0;
  long connecttimeout = 3L;
  long timeout = 5L;
  const char *debugfile = NULL;
  struct trace_data config;
  int debugascii = 0;
  const char *version = NULL;
  long ver = CURL_SSLVERSION_TLSv1_2;

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
#if LIBCURL_VERSION_PATCH >= 8
    }else if(strcmp(*argv, "--ip4_ttl") == 0)
    {
      if(--argc<1)
        break;
      ip4_ttl = atol(*(++argv));
    }
    else if(strcmp(*argv, "--dns_ip4_ttl") == 0)
    {
      if(--argc<1)
        break;
      dns_ip4_ttl = atol(*(++argv));
    }
    else if(strcmp(*argv, "--dns") == 0)
    {
      if(--argc<1)
        break;
      dns_strings = *(++argv);
#endif
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
        /**
         * 设置证书类型，此定制中使用"PKICM"
         */
        curl_easy_setopt(curl, CURLOPT_SSLENCCERTTYPE, "PKICM");

        /**
         * 设置证书类型，如果需要调用RSA密钥，就设置"rsa",
         * 如果要调用SM2密钥,就设置为"sm2"，如果要调用ECC密钥，就设置为"ecc" 
         * libcurl 内部会通过接口设置CA证书 ,本例中使用SM2*/
        curl_easy_setopt(curl, CURLOPT_SSLENCCERT, type);
        
        /**
         * 设置私钥类型，此定制中使用"PKICM"
         */
        curl_easy_setopt(curl, CURLOPT_SSLENCKEYTYPE, "PKICM");
   
        /**
         * 设置私钥类型，如果需要调用RSA密钥，就设置"rsa",
         * 如果要调用SM2密钥,就设置为"sm2"，如果要调用ECC密钥，就设置为"ecc" 
         * libcurl 内部会通过接口设置CA证书 ,本例中使用SM2*/
        curl_easy_setopt(curl, CURLOPT_SSLENCKEY, type);        
      }
#endif

      /* 如果需要验证证书链就设置CA证书（CURLOPT_CAINFO）,如果需要调用RSA密钥，就设置"rsa",
       * 如果要调用SM2密钥,就设置为"sm2"，如果要调用ECC密钥，就设置为"ecc" 
       * libcurl 内部会通过接口设置CA证书 ,本例中使用SM2*/
      /**
       * 如果设置 CURLOPT_SSL_VERIFYPEER 为0, 此选项无效 */
      curl_easy_setopt(curl, CURLOPT_CAINFO, type);

      /**
       * 如果需要验证服务端证书状态(OCSP Stapling), 则设置CURLOPT_SSL_VERIFYSTATUS 为1 */
      /**
       * 如果设置 CURLOPT_SSL_VERIFYPEER 为0, 此选项无效 */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);

      /**
       * 验证服务端证书主机名 */
      /**
       * 如果设置 CURLOPT_SSL_VERIFYPEER 为0, 此选项无效 */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

      /**
       * 设置证书类型，此定制中使用"PKICM"
       */
      curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PKICM");
 
      /**
       * 设置SSL版本
       */
      curl_easy_setopt(curl, CURLOPT_SSLVERSION, ver);

      /**
       * 设置证书类型，如果需要调用RSA密钥，就设置"rsa",
       * 如果要调用SM2密钥,就设置为"sm2"，如果要调用ECC密钥，就设置为"ecc" 
       * libcurl 内部会通过接口设置CA证书 ,本例中使用SM2*/
      curl_easy_setopt(curl, CURLOPT_SSLCERT, type);
      
      /**
       * 设置私钥类型，此定制中使用"PKICM"
       */
      curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PKICM");
 
      /**
       * 设置私钥类型，如果需要调用RSA密钥，就设置"rsa",
       * 如果要调用SM2密钥,就设置为"sm2"，如果要调用ECC密钥，就设置为"ecc" 
       * libcurl 内部会通过接口设置CA证书 ,本例中使用SM2*/
      curl_easy_setopt(curl, CURLOPT_SSLKEY, type);

      /** 设置超时 */
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

      /** 设置DNS，connect timeout */
      curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connecttimeout);

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
 
 #if LIBCURL_VERSION_PATCH >= 8
      if(ip4_ttl != 0) {
        res = curl_easy_setopt(curl, CURLOPT_LOCAL_IP4_TTL, ip4_ttl);
        if(res){
          fprintf(stderr, "%s\n", curl_easy_strerror(res));
          goto cleanup;
        }
      }

      if(dns_ip4_ttl != 0){
        res = curl_easy_setopt(curl, CURLOPT_DNS_LOCAL_IP4_TTL, dns_ip4_ttl);
        if(res){
          fprintf(stderr, "%s\n", curl_easy_strerror(res));
          goto cleanup;
        }
      }
      
      if(dns_strings){
        res = curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, dns_strings);
        if(res){
          fprintf(stderr, "%s\n", curl_easy_strerror(res));
          goto cleanup;
        }
      }
      
 #endif 
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
  cleanup:
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
 
  curl_global_cleanup();
  if(debugfile && config.stream){
    fclose(config.stream);
  }
 
  return 0;
}
