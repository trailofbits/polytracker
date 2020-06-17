#include <fstream>
#include <sstream>
#include <iostream>

int main(int argc, char * argv[]) {
	if (argc < 2) {
		std::cout << "Error! no file supplied!" << std::endl;
		return -1;
	}
	std::ifstream myfile;
	myfile.open(argv[1]);
	std::stringstream data;
	data << myfile.rdbuf();
	if (myfile.is_open()) {
		std::cout << data.rdbuf() << std::endl;
	}
	else {
		std::cout << "FAILED TO OPEN DATA" << std::endl;
		return -1;
	}
	return 0;
}
