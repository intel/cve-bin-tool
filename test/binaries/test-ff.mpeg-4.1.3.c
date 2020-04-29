#include <stdio.h>

int main() {
	printf("This program is designed to test the cve-bin-tool checker.");
	printf("It outputs a few strings normally associated with ffmepg 4.1.3.");
	printf("They appear below this line.");
	printf("------------------");
	printf("Codec '%s' is not recognized by FFmpeg.", "whatever");
	printf("%s version 4.1.3", "FFmpeg");

	return 0;
}
