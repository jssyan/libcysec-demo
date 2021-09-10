#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include <curl/curl.h>

// only for testing ,don't copy it 
int test_http_post(const char *address, int port, const unsigned char *in, size_t ilen, unsigned char **out, size_t *olen);

void hexdump(const unsigned char* s, int len) {
	int n;
	printf("(%d)\n", len);
	for (n = 0; n < len; n ++) {
		printf("%02x", s[n]);
		if (!((n + 1) % 8)) {
			printf("\n");
			continue;
		}
		if (!((n + 1) % 2)) {
			printf(" ");
			continue;
		}
	}
	printf("\n");
}

char* as_string(const char* s, int len) {
	char* r = x_malloc(len + 1);
	if(!r)
		return NULL;
	memcpy(r, s, len);
	return r;
}

char* as_hexstring(const unsigned char* s, int len) {
	char* r = x_malloc(len * 2 + 1);
	if(!r)
		return NULL;
	int n;
	for (n = 0; n < len; n ++) {
		sprintf(r + (n * 2), "%02x", s[n]);
	}
	return r;
}

static
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;
 
  unsigned int width = 0x10;
 
  if(nohex)
    /* without the hex output, we can fit more on screen */ 
    width = 0x40;
 
  fprintf(stream, "%s, %10.10zu bytes (0x%8.8zu)\n",
          text, size, size);
 
  for(i = 0; i<size; i += width) {
 
    fprintf(stream, "%4.4zu: ", i);
 
    if(!nohex) {
      /* hex not disabled, show it */ 
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stream, "%02x ", ptr[i + c]);
        else
          fputs("   ", stream);
    }
 
    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */ 
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stream, "%c",
              (ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */ 
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stream); /* newline */ 
  }
  fflush(stream);
}

int demo_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  struct trace_data *config = (struct trace_data *)userp;
  const char *text;
  (void)handle; /* prevent compiler warning */
  FILE *stream = NULL;
 
  if (!config)
  	return 0;

  stream = (config->stream) ? config->stream: stderr;

  switch(type) {
    case CURLINFO_TEXT:
      fprintf(stream, "== Info: %s", data);
      /* FALLTHROUGH */ 
    default: /* in case a new one is introduced to shock us */ 
      return 0;

    case CURLINFO_HEADER_OUT:
      text = "=> Send header";
      break;
    case CURLINFO_DATA_OUT:
      text = "=> Send data";
      break;
    case CURLINFO_SSL_DATA_OUT:
      text = "=> Send SSL data";
      break;
    case CURLINFO_HEADER_IN:
      text = "<= Recv header";
      break;
    case CURLINFO_DATA_IN:
      text = "<= Recv data";
      break;
    case CURLINFO_SSL_DATA_IN:
      text = "<= Recv SSL data";
      break;
  }
 
  dump(text, stream, (unsigned char *)data, size, config->trace_ascii);
  return 0;
}

