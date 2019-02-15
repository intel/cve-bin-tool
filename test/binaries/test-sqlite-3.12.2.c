#include <stdio.h>

int main() {
	printf("This program is designed to test the cve-bin-tool checker.");
	printf("It outputs a few strings normally associated with sqlite3 3.12.2");
	printf("They appear below this line.");
	printf("------------------");
	printf("2016-04-18 17:30:31 92dc59fd5ad66f646666042eb04195e3a61a9e8e");
	printf("ESCAPE expression must be a single character");

	return 0;
}
