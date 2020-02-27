#include <stdlib.h>
#include <stdio.h>
#include <jpeglib.h>

int parse_jpeg(char *path) {
	struct jpeg_decompress_struct cinfo;
	struct jpeg_error_mgr jerr;
	JSAMPROW row_pointer[1];
	FILE *infile = fopen(path, "rb");
	unsigned long location = 0;
	int i = 0;
        unsigned char *raw_image;

	if(!infile) {
		printf("Error opening jpeg file %s!\n", path);
		return 128;
	}

	cinfo.err = jpeg_std_error(&jerr);

	jpeg_create_decompress(&cinfo);

	jpeg_stdio_src(&cinfo, infile);

	jpeg_read_header(&cinfo, TRUE);


	jpeg_start_decompress(&cinfo);
	printf("parsed %d JPEG components of %s\n", cinfo.num_components, path);

	/* raw_image = (unsigned char*)malloc(cinfo.output_width*cinfo.output_height*cinfo.num_components); */

	/* row_pointer[0] = (unsigned char *)malloc(cinfo.output_width*cinfo.num_components); */

	/* while(cinfo.output_scanline < cinfo.image_height) { */
        /*     jpeg_read_scanlines(&cinfo, row_pointer, 1); */
        /*     for(i=0; i<cinfo.image_width*cinfo.num_components;i++) { */
        /*         raw_image[location++] = row_pointer[0][i]; */
        /*     } */
	/* } */

	/* jpeg_finish_decompress(&cinfo); */
	/* jpeg_destroy_decompress(&cinfo); */
	/* free(row_pointer[0]); */
	fclose(infile);

	return 0;
}

int main(int argc, char** argv) {
    int i;
    if(argc < 2) {
        return 1;
    }
    for(i=1; i<argc; ++i) {
        int ret = parse_jpeg(argv[i]);
        if(ret != 0) {
            return ret;
        }
    }
    return 0;
}
