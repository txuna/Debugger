#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <ctype.h>
#include <linux/types.h>
#include "elf_parser.h"
#include "dumpcode.h"

#define BUF_SIZE 4096

void check_symtab(int* check, int e_shnum, Elf32_Shdr* section);
void input(int number, Elf32_Sym* symbol, int file);

int main(int argc, char** argv) 
{
	int check=0; 
	Elf32_Ehdr elf;
	Elf32_Shdr* section_header;
	Elf32_Sym* symbol;
	int return_check;
	int file; 
	int i;
	int strtab_offset, symtab_offset; 
	int symbol_number;

	if(argc!=2)
	{
		perror("Error argc");
		exit(1);
	}
	file = open(argv[1], O_RDONLY); 
	if(file == -1)
	{
		perror("Error file");
		exit(1);
	}
	return_check=check_elf(file); //elf인지 확인한다. 
	
	if(return_check)
	{
		printf("This is not ELF\n");
		close(file);
		exit(1);
	}
	
	elf = elf_header(file); //elf의 header를 출력한다. 
	section_header = elf_section_header(elf, file); //elf의 섹션헤더를 출력한다. 

	check_symtab(&check, elf.e_shnum, section_header); //symtab의 위치를 확인한다. 


	strtab_offset = ((section_header+elf.e_shstrndx-1)->sh_offset); //strtab의 offset 
    symtab_offset = (section_header+check)->sh_offset;				//symtab의 offset 
	symbol_number = strtab_offset - symtab_offset; 
	symbol_number = symbol_number / 0x10; 								//0x10 : struct의 크기 


	symbol=symbol_table(strtab_offset,symtab_offset,file); //반환값은 Elf32_Sym의 힙메모리 주소값이다. 
	input(symbol_number,symbol, file);

	free(section_header);
	free(symbol); 
	close(file);
	return 0;
}

void check_symtab(int* check, int e_shnum, Elf32_Shdr* section)
{
	int i;
	for(i=0;i<e_shnum;i++)
	{
		if((section+i)->sh_type == 0x2)
		{
			*check = i;
			break;
		}
	}
	if(!(check))
	{
		perror("Umm... This is stripped file!\n");
		exit(1);
	}
}

void input(int number, Elf32_Sym* symbol,int file)
{
	int index;
	unsigned char symbol_context[4096]; 
	int symbol_address;
	int symbol_size;
	while(1)
	{
		printf("\n\nInput want to print symbol index : ");
		scanf("%d", &index);
		if(index < 0 || index > number)
		{
			continue;
		}
	symbol_address = symbol[index].st_value; 
	symbol_size = symbol[index].st_size;

	lseek(file, symbol_address, SEEK_SET); 
	read(file, symbol_context, BUF_SIZE); 
	dumpcode(symbol_context, symbol_size); 	
	}
}
