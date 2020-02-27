#include <fstream>
#include <kaitai/kaitaistream.h>
#include "jpeg.h"

int main(const int argc, const char** argv) {
    std::ifstream is(argv[1], std::ifstream::binary);
    kaitai::kstream ks(&is);
    jpeg_t data(&ks);
    return 0;
}
