#include <string>
#include <fstream>
#include <iostream>
#include <string>

//Expected taint data to have 10 in cmp
void bar(std::string x) {
	if (x[10] == 'c') {
		std::cout << "10th char is c" << std::endl;
	}
}

void baz(std::string x) {
	bar(x);
}
//Expected taint data to have 0 in cmp 
void check_first_last(std::string json) {
	if (json[0] == '{') {
		baz(json);
	}
}

void out_everything(std::string json) {
	std::ofstream outfile;
	outfile.open("/tmp/junk.json");
	if (outfile.is_open()) {
		outfile << json;
		outfile.close();
	}
}

int main() {
	std::cout << "Hello world" << std::endl;
	std::ifstream myfile;
	myfile.open("test_data/polytracker_process_set.json");
	std::string line;
	std::string json;
	if (myfile.is_open()) {
		while (getline(myfile, line)) {
			json += line + '\n';
		}
		check_first_last(json);
	}
	else {
		std::cout << "ERROR FAILED TO PARSE JSON" << std::endl;
	}
	return 0;
}
