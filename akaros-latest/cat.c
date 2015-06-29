
#include <stdio.h>

int main(int argc, char* argv[])
{
	FILE* fin;
	unsigned char buf[8192];
	int bytes_read;
	unsigned int checksum=0;
	
	if(argc < 2)
	{
		printf("Usage: %s filename\n", argv[0]);
		return 0;
	}
	fin = fopen(argv[1], "rb");
	if(fin == NULL)
	{
		printf("Cannot open file %s\n", argv[1]);
		return 1;
	}
	while(!feof(fin))
	{
		int i;
		bytes_read = fread(buf, 1, sizeof(buf), fin);
		for(i = 0; i<bytes_read; ++i)
		{
			//if(!(i & 0xf))
			//	putchar('\n');
			checksum += buf[i];
			//printf("%02x ", (unsigned int)buf[i]);
			putchar(buf[i]);
		}
	}
	printf("\nCheck Sum: %x\n", checksum);
	fclose(fin);
}


