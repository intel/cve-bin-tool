#include <stdio.h>

int main() {
	printf("This program is designed to test the cve-bin-tool checker.");
	printf("It outputs a few strings normally associated with libdb 11.2.5.1.29");
	printf("They appear below this line.");
	printf("------------------");
	printf("BDB1568 Berkeley DB library does not support DB_REGISTER on this system");
	printf("Berkeley DB 11g Release 2, library version 11.2.5.1.29: (date goes here)");

	return 0;
}
