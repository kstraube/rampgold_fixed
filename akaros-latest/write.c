
#include <stdio.h>

int main(int argc, char* argv[])
{
	FILE* fin;
	int i;
	
	if(argc < 3)
	{
		printf("Usage: %s filename length\n", argv[0]);
		return 0;
	}
	fin = fopen(argv[1], "w");
	if(fin == NULL)
	{
		printf("Cannot open file %s\n", argv[1]);
		return 1;
	}
	for(i=0; i<atoi(argv[2]); ++i)
	{
		fputc(i % 10 + '0', fin);

	}
	fclose(fin);
}

