#include <stdio.h>

int main() {
	printf("This program is designed to test the cve-bin-tool checker.");
	printf("It outputs a few strings normally associated with sqlite3 3.27.1");
	printf("They appear below this line.");
	printf("------------------");
	printf("2019-10-10 20:19:45 18db032d058f1436ce3dea84081f4ee5a0f2259ad97301d43c426bc7f3df1b0b");
	printf("ESCAPE expression must be a single character");

	return 0;
}
