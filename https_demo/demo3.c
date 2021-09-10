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
  printf(" TLS client no verify .\n");
  printf("--url the https URL (like:https://192.168.10.130:445)\n");
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
   * 调用SM2密钥对，进行TLS握手，此示例为单项验证(不验证服务端证书)
*/ 
 
int main(int argc, char ** argv)
{
  CURL *curl;
  CURLcode res;
  const char *default_url="https://192.168.10.130:445";
  const char *url = NULL;
  char errbuf[CURL_ERROR_SIZE]={0};
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
    } else if(strcmp(*argv, "--help") == 0 ){
      usage();
    } else if(strcmp(*argv, "-v") == 0 ) {
      verbose = 1;
    }  else if(strcmp(*argv, "--connecttimeout") == 0 ){
      if(--argc<1)
        break;
      connecttimeout = atol(*(++argv));
    } else if(strcmp(*argv, "--timeout") == 0 ) {
      if(--argc<1)
        break;
      timeout = atol(*(++argv));
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
      /* 验证服务端主机，验证为1，不验证为0 */ 
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
 
       /**
       * 设置SSL版本
       */
      curl_easy_setopt(curl, CURLOPT_SSLVERSION, ver);

      /** 不使用信号量，在多线程中如果设置超时，超时使用的是线程不安全的信号机制，所以去掉信号 */
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL , 1L);

      /** 不使用环境变量中的代理 */
      curl_easy_setopt(curl, CURLOPT_PROXY, "");
      
      /* provide a buffer to store errors in */
      curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
      

      /** 设置 timeout */
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

      /** 设置DNS，connect timeout */
      curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connecttimeout);

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