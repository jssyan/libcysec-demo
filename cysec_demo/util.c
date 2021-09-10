#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

void hexdump(const unsigned char *data, size_t data_cb) {
    size_t i = 0, k = 0;
    char hexline[126] = "";
    char hexbytes[11] = "";

    for (i=0; i<data_cb; i++) {
    	sprintf(hexbytes, "0x%02X|", data[i]);
    	strcat(hexline, hexbytes);

    	if ((((i+1)%16==0) && (i!=0)) || (i+1==data_cb)) {
    		k++;
    		printf("l%zu: %s\n", k, hexline);
    		memset(&hexline[0],0, sizeof(hexline));
    	}
    }
}


char* as_string(const char* s, int len) {
	char* r = x_malloc(len + 1);
	memcpy(r, s, len);
	return r;
}

char* as_hexstring(const unsigned char* s, int len) {
	char* r = x_malloc(len * 2 + 1);
	int n;
	for (n = 0; n < len; n ++) {
		sprintf(r + (n * 2), "%02x", s[n]);
	}
	return r;
}

