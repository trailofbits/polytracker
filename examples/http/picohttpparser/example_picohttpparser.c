#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "picohttpparser.h"

#define ERROR_IO -1
#define ERROR_PARSE -2
#define ERROR_REQUEST_TOO_LONG -3

int parse_http_request(char *fpath) {
    FILE *infile = fopen(fpath, "rb");
	unsigned long location = 0;
	int i = 0;
        unsigned char *raw_image;

	if(!infile) {
		printf("Error opening http file %s!\n", fpath);
		return 128;
	}

    char buf[4096], *method, *path;
    int pret, minor_version;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
    ssize_t rret;

    while (1) {
        /* read the request */
        while ((rret = read(fileno(infile), buf + buflen, sizeof(buf) - buflen)) == -1 && errno == EINTR)
            ;
        if (rret <= 0)
            return ERROR_IO;
        prevbuflen = buflen;
        buflen += rret;
        /* parse the request */
        num_headers = sizeof(headers) / sizeof(headers[0]);
        pret = phr_parse_request(buf, buflen, &method, &method_len, &path, &path_len,
                                &minor_version, headers, &num_headers, prevbuflen);
        if (pret > 0)
            break; /* successfully parsed the request */
        else if (pret == -1)
            return ERROR_PARSE;
        /* request is incomplete, continue the loop */
        assert(pret == -2);
        if (buflen == sizeof(buf))
            return ERROR_REQUEST_TOO_LONG;
    }

    printf("request is %d bytes long\n", pret);
    printf("method is %.*s\n", (int)method_len, method);
    printf("path is %.*s\n", (int)path_len, path);
    printf("HTTP version is 1.%d\n", minor_version);
    printf("headers:\n");
    for (i = 0; i != num_headers; ++i) {
        printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
            (int)headers[i].value_len, headers[i].value);
    }

    fclose(infile);
    return 0;
}

int main(int argc, char *argv[]) {
    int i;
    if(argc < 2) {
        return 1;
    }
    for(i=1; i<argc; ++i) {
        int ret = parse_http_request(argv[i]);
        if(ret != 0) {
            return ret;
        }
    }
    return 0;
}