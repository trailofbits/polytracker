/*
 * test_vector.cpp
 *
 *  Created on: Jun 1, 2020
 *      Author: carson
 */
#include <fstream>
#include <iostream>
#include <vector>

/*
 * This testcase checks to see that we can pass data through cxx standard
 * templates like vector
 */

class VectorContainer {
public:
  VectorContainer(std::vector<std::string> str_vec) { string_vec = str_vec; }
  ~VectorContainer() {}
  // It might not mark as tainted in this function, but it should here or in
  // some cxx function
  void printAllItems() {
    for (auto it = string_vec.begin(); it != string_vec.end(); it++) {
      std::cout << *it << std::endl;
    }
  }
  std::string getString() { return string_vec.front(); }

private:
  std::vector<std::string> string_vec;
};

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cout << "Error! no file supplied!" << std::endl;
    return -1;
  }
  std::ifstream myfile;
  myfile.open(argv[1]);
  std::string data;
  std::string curr_line;
  std::vector<std::string> string_vec;
  if (myfile.is_open()) {
    while (getline(myfile, curr_line)) {
      data += curr_line;
    }
    string_vec.push_back(data);
  } else {
    std::cout << "FAILED TO OPEN DATA" << std::endl;
    return -1;
  }
  VectorContainer vec(string_vec);
  vec.printAllItems();
  myfile.close();
  std::string tainted_string = vec.getString();
  if (tainted_string[0] == 'w') {
    std::cout << "" << std::endl;
  }
  return 0;
}
