int check_elf(int file)
{
	ssize_t check; 
	char value[16];
	int i;
	int magic=1; 
	lseek(file, 0, SEEK_SET);
	for(i=0;i<16;i++)
	{
		read(file, &value[i], 1); 
	}
	if(value[0] == 0x7F && value[1] == 0x45 && value[2] == 0x4c && value[3] == 0x46)
	{
		magic = 0;
	}
	if(magic)
	{
		return 1;
	}
	return 0;
}	

/*
// 32-bit ELF base types.  
typedef __u32 Elf32_Addr; 
typedef __u16 Elf32_Half; 
typedef __u32 Elf32_Off; 
typedef __s32 Elf32_Sword;
typedef __u32 Elf32_Word; 
*/
#define EL_NIDENT 16 
/*
typedef struct elf32_hdr{
    unsigned char e_ident[EL_NIDENT]; //=> 파일이 object파일임을 나타냄. 기계 독립적인 데이터 제공 
    Elf32_Half    e_type;             //=> Object 파일의 타입을 표시 
    Elf_Half      e_machine;          //=> 아키텍쳐 정보를 표시 (32인지 64인지) 
    Elf_Word      e_version;          //=> Object 파일의 버전 정보 
    Elf_Addr      e_entry;  		  //=> 가상주소 (시작점 ), 프로그램을 어디로
    Elf_Off       e_phoff;            //=> 프로그램 헤더 파일 옵셋을 나타냄
    Elf_Off       e_shoff;            //=> 섹션 헤더 테이블의 파일 옵셋을 나타냄 
    Elf32_Word    e_flags             //=> 사용 X
    Elf32_Half    e_ehsize;           //=> ELF 헤더의 크기를 가짐 
    Elf32_Half    e_phentsize;        //=> 파일의 프로그램 헤더파일에 있는 한 엔트리의 크기를 나타냄
    Elf32_Half    e_phnum;            //=> 프로그램 헤더 테이블에 들어있는 모든 엔트리의 수를 나타냄 
    Elf32_Half    e_shentsize;        //=> 섹션 헤더의 크기를 나타냄.
    Elf32_Half    e_shnum;            //=> 섹션 헤더 테이블에 있는 엔트리의 수를 가짐. 
    Elf32_Half    e_shstrndx;         
	//=> 섹션의 이름을 나타내는 스트링의 테이블과 관련된 엔트리의 섹션 헤더 테이블 인덱스를 가진다. 
} Elf32_Ehdr;
*/
Elf32_Ehdr elf_header(int file)
{
	Elf32_Ehdr elf32; 
	//Elf64_Ehdr elf64;

	ssize_t check; 
	int i;
	
	lseek(file, 0, SEEK_SET);	
	read(file, &elf32, sizeof(elf32)); 

	printf("magic:	");
	for(i=0;i<16;i++)
		printf("%X ", elf32.e_ident[i]); 
	printf("\n");

	printf("%c[1;31m",27);
	if(elf32.e_ident[4] == 1)
		printf("Class:					ELF32\n");
	else if(elf32.e_ident[4] == 2)
	{
		printf("Class:					ELF64\n"); 
		printf("Sorry! debugger want 32bit binary!\n");
		exit(1);
		//return -1;
	}
	else
		perror("Error!");
	printf("%c[0m",27);

	if(elf32.e_ident[5] == 1)
		printf("Data:					2's complement, little endian\n");
	else if(elf32.e_ident[5] == 2)
		printf("Data:					1's complement, big endian\n");
	else
		perror("Error!");

	if(elf32.e_ident[6] == 1)
		printf("Version:				1 (current)\n");
	else if(elf32.e_ident[6] == 2)
		printf("Version:				setting....\n");
	else
		perror("Error!");

	printf("OS/ABI:					UNIX - System 	V\n");
	printf("ABI Version:				0\n"); 
	
	printf("%c[1;31m",27);
	if(elf32.e_machine ==3)
		printf("Machine:				Intel 80386\n");
	else if(elf32.e_machine == 62)
		printf("Machine:			Advance Micro Devices X86-64\n"); 
	else
		printf("Machine:			setting.....\n");
	printf("%c[0m",27);

	if(elf32.e_type == 0)
		printf("Type:				    		   NONE\n");
	else if(elf32.e_type == 1) 
		printf("Type:       			           REL\n");
	else if(elf32.e_type == 2)
		printf("Type:           		   	  	   EXEC\n");
	else if(elf32.e_type == 3)
		printf("Type:        	    		       DYN\n");
	else if(elf32.e_type == 4)
		printf("Type:               	    	   CORE\n");
	else
		printf("Type:				setting....\n");

	printf("Version:				0x1\n");
	//printf("=========================================\n");

	printf("%c[1;31m",27);
	printf("Entry Point Address(.text):		0x%X\n",elf32.e_entry);
	printf("%c[0m",27);
	printf("Flags:					%X\n",elf32.e_flags); 
	printf("Start of program headers:		0x%X\n",elf32.e_phoff);
	printf("Start of section headers:		0x%X\n",elf32.e_shoff);
	printf("Size of program headers:		%X (bytes)\n",elf32.e_phentsize);
	printf("Size of section headers:		%X (bytes)\n",elf32.e_shentsize);
	printf("Number of program headers:		%X\n",elf32.e_phnum);
	printf("Size of ELF Header:			%X (bytes)\n",elf32.e_ehsize);
	printf("Number of section headers:		%X\n",elf32.e_shnum);
	printf("Section header string table index:	%d\n",elf32.e_shstrndx);

	//printf("\n\n\n %X \n\n\n",elf32.e_shstrndx);

	return elf32;
}

Elf32_Shdr* elf_section_header(Elf32_Ehdr elf, int file)
{
	char sym[60][30]; //나중에 동적할당으로 크기 지정할 수 있게 바꾸자
	char name; 
	int check=0;
	//static Elf32_Shdr section_header[30];
	//const char *const name; 
	Elf32_Shdr* section_header = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr)*elf.e_shnum); //일단 30개 해놓자  
	int i;
	int j=0;
	lseek(file, elf.e_shoff, SEEK_SET); 
	for(i=0;i<elf.e_shnum;i++)
	{
		read(file, &section_header[i], sizeof(Elf32_Shdr));
	}
	printf("\nThere are %d section headers, starting at offset %X\n", elf.e_shnum, elf.e_shoff); 

	printf("\nSection Headers:\n"); 
	printf("[Nr] Name\t\t\tAddr\tOff\tSize\n"); 
	
	//lseek(file, section_header[28].sh_offset, SEEK_SET); 

	for(i=0;i<elf.e_shnum;i++)
	{
		//일단 shstrtab값(11)을 28로 가정하고 진행했음. 따로 구해야 하는데 구하는 방법이...
		lseek(file, section_header[elf.e_shstrndx].sh_offset+section_header[i].sh_name,SEEK_SET);
		while(read(file, &name, 1))
		{
			if(name == '\0')
			{
				break;
			}
			sym[i][j] = name;
		    j++;	
		}
		sym[i][j] = '\0';
		j=0;
	}

	for(i=0;i<elf.e_shnum;i++)
	{
		printf("[%-2d] %s\t\t\t0x%X\t0x%X\t%X\n",i,sym[i], section_header[i].sh_addr, section_header[i].sh_offset, section_header[i].sh_size);
	}
	return section_header;
}


Elf32_Sym* symbol_table(int strtab_offset, int symtab_offset ,int file)
{	//중요한건 심볼테이블에 들어있는 심볼의 개수를 파악하는것! 
	//또한, 각 심볼이 해당하는 Name값을 알아내는것 
	/*
	 typdef struct {
    Elf32_Word st_name;     //심볼 이름의 문자 표현이 있는 심볼 스트링 테이블을 가리키는 인덱스
    Elf32_Addr st_value;    //관련된 심볼 값, 주소값 
    Elf32_Word st_size;     //심볼의 크기 
    unsigned char st_info;  //심볼의 타입과 묶인 속성 
    unsigned char st_other; // 0   
    Elf32_Half st_shndx;    //관련된 섹션 헤더 테이블 인덱스를 저장 
} Elf32_Sym; 
	 */
	//사용자는 이름 옆에 붙여진 인덱스값으로 검색할 수 있게
	int size = (strtab_offset - symtab_offset) / 0x10;  //symbol의 개수 0x10은 구조체 크기 
	//static Elf32_Sym symbol[70]; //동적할당으로 반환할까
	Elf32_Sym* symbol = (Elf32_Sym*)malloc(sizeof(Elf32_Sym)*size);
	int type;
	int bind;
    char* type_string[size]; 
	char* bind_string[size];
	char name;	
	char sym_name[3000][50]; 	//symbol들의 이름을 넣는다. (나중에 동적할당으로 변환시키자) 
	int i;
	int j;

	lseek(file, symtab_offset, SEEK_SET);
	for(i=0;i<size;i++)
	{
		read(file, &symbol[i], sizeof(Elf32_Sym));  //st_info값은 type값과 bind값이 합쳐져 있음 
		type = symbol[i].st_info & 0xf; 
		bind = symbol[i].st_info >> 4;
		if(type == 0)
			type_string[i] = "NOTYPE"; 
		else if(type == 1)
			type_string[i] = "OBJECT";
		else if(type == 2)
			type_string[i] = "FUNC";
		else if(type == 3)
			type_string[i] = "SECTION";
		else if(type == 4)
			type_string[i] = "FILE";
		else if(type == 5)
			type_string[i] = "COMMON";
		else if(type == 6)
			type_string[i] = "TLS";
		else if(type == 10)
			type_string[i] = "LOOS"; 
		else if(type == 12)
			type_string[i] = "HIOS";
		else if(type == 13)
			type_string[i] = "LOPROC";
		else if(type == 15)
			type_string[i] = "HIPROC";
		else
			type_string[i] = "ERROR";

		if(bind == 0)
			bind_string[i] = "LOCAL"; 
		else if(bind == 1)
			bind_string[i] = "GLOBAL"; 
		else if(bind == 2)
			bind_string[i] = "WEAK";
		else if(bind == 10)
			bind_string[i] = "LOOP";
		else if(bind == 12)
			bind_string[i] = "HIOS";
		else if(bind == 13)
			bind_string[i] = "LOPROC";
		else if(bind == 15)
			bind_string[i] == "HIPROC"; 
		else
			bind_string[i] == "ERROR";
	}
//st_name 값이 strtab의 인덱스 값 
	//lseek(file, strtab_offset, SEEK_SET); //strtab의 시작점
	for(i=0;i<size;i++)
	{
		lseek(file, strtab_offset+symbol[i].st_name, SEEK_SET);
		while(read(file, &name, 1))
		{
			if(name == '\0')
			{
				break;
			}
			sym_name[i][j] = name;
			j++;
		}
		sym_name[i][j] = '\0'; 
		j=0;
	}	
  
	printf("\nSymbol table '.symtab' contains %d entries:\n",size); 
	printf("\nNum:\tValue\t\tSize\tType\tBind\tName\n");
	for(i=0;i<size;i++)
	{
		printf("[%-2d]:\t%08X\t%X\t%s\t%s\t%s [%-2d]\n",i,symbol[i].st_value, symbol[i].st_size, type_string[i], bind_string[i], sym_name[i], symbol[i].st_name); 
		//sleep(1);
	}
	return symbol; //symbol[i].st_name과 symbol[i].st_value(address)를 반환해서 가공해야 한다. 
}


