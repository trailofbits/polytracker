#include <string>
#include <fstream>
#include <iostream>
#include <string>

void union_bytes(std::string& json) {
	if (json[0] == json[1]) {
		printf("matching!\n");
	}
	else {
		printf("not matching!\n");
	}	
}

int main(int argc, const char * argv[]) {
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
		union_bytes(json);
	}
	else {
		std::cout << "FAILED TO OPEN DATA" << std::endl;
		return -1;
	}
	return 0;
}
