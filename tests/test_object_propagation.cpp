#include <fstream>
#include <string>
#include <iostream>
#include <sstream>

/*
 * This is a simple test case to test tracking through object instantiation
 * and getters/setters
 *
 * It also tests to see if the tracking handles copying objects with tainted data appropriately
 */

class Container {
public:
	Container(std::string str) : stored_string(str) {}
	~Container() {}
	std::string getString() {
		return stored_string;
	}
	void setString(std::string new_str) {
		stored_string = new_str;
	}
private:
	std::string stored_string;
};

/*
 * Should be tainted as its a copy of a tainted object
 */
void copied_tainted_object(Container c) {
	std::string tainted_str = c.getString();
	if (tainted_str[0] == 'a') {
		std::cout << tainted_str[0] << std::endl;
	}
}

/*
 * Should be tainted as its just a string
 * Could be tainted by everything, but maybe its deeper in the libcxx
 * Should have whatever the mapping for byte 0 is in the cmp bytes.
 */
void tainted_string(std::string str) {
	char s = str[0];
	if (s == 'a') {
		std::cout << "first char is a!" << std::endl;
	}
	std::cout << str << std::endl;
}

/*
 * Called after the string is set with a new string, clearing the taint.
 */
void no_tainted_string(Container c) {
	std::string tainted_str = c.getString();
	if (tainted_str[0] == 'a') {
		std::cout << tainted_str[0] << std::endl;
	}
}

int main(int argc, char * argv[]) {
	if (argc < 2) {
		std::cout << "Error! no file supplied!" << std::endl;
		return -1;
	}
	std::ifstream myfile;
	myfile.open(argv[1]);
	std::string data;
	std::string curr_line;
	if (myfile.is_open()) {
		while (getline(myfile, curr_line)) {data += curr_line;}
		auto new_cont = Container(data);
		copied_tainted_object(new_cont);
		tainted_string(new_cont.getString());
		new_cont.setString("test");
		no_tainted_string(new_cont);
	}
	else {
		std::cout << "FAILED TO OPEN DATA" << std::endl;
		return -1;
	}
	return 0;

}


