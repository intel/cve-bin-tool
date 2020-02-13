#include <stdio.h>

int main() {
	printf("This program is designed to test the cve-bin-tool checker.");
	printf("It outputs a few strings normally associated with png 1.6.36.");
	printf("They appear below this line.");
	printf("------------------");
	printf("Application uses deprecated png_write_init() and should be recompiled");

	return 0;
}
