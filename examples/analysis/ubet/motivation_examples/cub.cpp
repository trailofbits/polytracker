#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    int i = 5000;
    if(argc > 1) {
	int j = i * i - (int)*argv[argc - 1];
	std::string line;
	std::getline(std::cin, line);
	std::cout << line << "\n" << j << std::endl;
        return j << -2;
    } else {
        return 0;
    }
}
