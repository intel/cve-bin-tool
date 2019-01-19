#include <stdio.h>

int main() {
	printf("This program is designed to test the cve-bin-tool checker.");
	printf("It outputs a few strings normally associated with libxml2 2.9.0");
	printf("They appear below this line.");
	printf("------------------");
	printf("/libxml2-2.9.0/");
	printf("xmlNewElementContent : name != NULL !");

	return 0;
}
