#include <stdio.h>
#include <string.h>

int main(void)
{
	char arr[] = "ebp-32"; 
	char* left = strtok(arr, "-"); 
	char* right = strtok(NULL, "-"); 
	printf("%s %s\n", left, right);
	return 0;
}
