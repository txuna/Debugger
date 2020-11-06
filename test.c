#include <stdio.h>

int main(void){
	unsigned int num = 0x12345678;
	printf("%x\n", num);
	unsigned int swapped = ((num >> 24)&0xff) | ((num << 8)&0xff0000) | ((num >> 8)&0xff00) | ((num<<24)&0xff000000); 
	printf("%x\n", swapped);
	return 0;
}
