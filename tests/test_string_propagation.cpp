#include <fstream>
#include <iostream>
#include <string>

/*
 * This is a simple test case that tests for taint source acquisition via
 * ifstream, and some simple propagation through functions and targeted checks.
 */

// Should touch byte 1 after process
void bar(std::string x) {
  if (x[1] == 'c') {
    std::cout << "2nd char is c" << std::endl;
  } else {
    std::cout << "2nd char is not c" << std::endl;
  }
}

void baz(std::string x) { bar(x); }

// Should touch byte 0 after process
void check_first_last(std::string json) {
  if (json[0] == '{') {
    baz(json);
  }
}

// Should touch the entire file, but its possible that it goes into a cxx lib
// instead, so its hard to see.
void out_everything(std::string json) {
  std::ofstream outfile;
  outfile.open("/tmp/junk.json");
  if (outfile.is_open()) {
    outfile << json;
    outfile.close();
  }
}

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cout << "Error! no file supplied!" << std::endl;
    return -1;
  }
  std::ifstream myfile;
  myfile.open(argv[1]);
  std::string line;
  std::string json;
  if (myfile.is_open()) {
    while (getline(myfile, line)) {
      json += line + '\n';
    }
    check_first_last(json);
    out_everything(json);
  } else {
    std::cout << "FAILED TO OPEN DATA" << std::endl;
    return -1;
  }
  return 0;
}
