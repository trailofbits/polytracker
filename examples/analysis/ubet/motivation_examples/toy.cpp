#if defined(PRODUCTION)
  #define NDEBUG
#endif

#include <cassert>
#include <cstdlib>

int main(int argc, char* argv[]) {
    if(argc > 1) {
        int shift = std::atoi(argv[1]);
        assert(shift > 0 && shift < 32);
        return 0xff << shift;
    } else {
        return 0;
    }
}
