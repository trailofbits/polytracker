#include <fstream>
#include <iostream>
/*
 * This checks to see that we are able to acquire taint source for ifstream
 * Getline is known/assumed to work here
 */

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    std::cout << "Error! no file supplied!" << std::endl;
    return -1;
  }
  std::ifstream myfile;
  myfile.open(argv[1]);
  std::string line;
  std::string data;
  if (myfile.is_open()) {
    // Taint source
    while (getline(myfile, line)) {
      data += line + '\n';
    }
    std::cout << data << std::endl;
  } else {
    std::cout << "Error, file not open!" << std::endl;
    return -1;
  }
  if (data[0] == 'a') {
    std::cout << "Touched first tainted byte" << std::endl;
  }
  return 0;
}
