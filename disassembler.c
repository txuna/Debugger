#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <ctype.h>
#include <elf.h>
#include <linux/types.h>
#include <errno.h>
//#include "dumpcode.h"

/*============Variable===========*/
extern int errno; 
char* regs8[8] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
char* regs16[8] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
char* regs32[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"}; 
char* segreg[6] = {"cs", "ss", "ds", "es", "fs", "gs"};
char* sib_base[8] = {"eax", "ecx", "edx", "ebx", "esp", "", "edi"};
char* scale_index[8] = {"eax", "ecx", "edx", "ebx", "", "ebp", "esi", "edi"};
char* mov_segment[6] = {"es", "cs", "ss", "ds", "fs", "gs"}; //mov같은 경우 위 segment_override와 순서가 다름. 
//typedef enum segment_registe {cs=0x2e, ss=0x36, ds=0x3e, es=0x26, fs=0x64, gs=0x65}Segment; 

//Segment seg_reg; 

struct Symbol_Meta{ //각 각의 심볼들의 이름과 address 
	char sym_name[100]; 
	int offset; 
	int size; 
};

struct Copy_Symbol_Meta{
	char** sym_name; 
	int* offset;
    int size; 	
}; 

struct Copy_Symbol_Meta copy_symbol_meta; 

//int sym_size; //symbol의 개수 
int byte_ptr = 0;
int dword_ptr = 0;
int word_ptr = 0; 
int segment_override=0;     //0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65
int operand_size=0; 		//0x67
int operand_address=0; 		//0x66
int lock=0;				    //0xf0, 
int rep=0;  				//0xf3
int repn =0;				//0xf2
int some_address = 0;		//각 명령어의 address를 표시. 
int check_prefix_line = 0;  
int two_byte_opcode = 0;
int three_byte_opcode = 0; 
//그냥 따로 함수를 만들어서 바로 출력하게 하자. 그리고 prefix값을 확인해서 check_prefix_line값이 2이상이면 pass
/*================================*/

/*============Fuction================================================================*/
//void command_line(); 
void setup(char* binary, char* file_name, int argu_number); 
char* command_line(char* file_name, unsigned char* file, int file_vol, struct Symbol_Meta* symbol_meta, int symbol_number);
void print_some_address(unsigned char* file, int* index);
void sib_func(unsigned char* file, int* index, int disp, char* sib_field);
void disp_func(unsigned char* file, int* index, int disp, char* disp_field);
void segment_sprintf(char* segment);	//세그먼트 레지스터를 넣을 문자열을 설정해줌   
char* file_to_heap(char* name, int* file_vol); 
int disasm(unsigned char* file, int file_vol, struct Symbol_Meta* symbol_meta,  char* input_symbol, int symbol_number);
void remove_char(char* str);
char* dec_to_hex(int decimal);
void prefix(char* rm_field); //이 함수안에서 segment_sprintf를 호출하자. 
void rep_prefix_cat(char* rm_field);
int check_elf(int file); 
/*==================================================================================*/
char* r16r32_rm8(unsigned char* file, int* index);
char* r16r32_rm16(unsigned char* file, int* index);
char* moffset16_32(unsigned char* file, int* index); 
char* rel8(unsigned char* file, int* index); 
char* rm8(unsigned char* file, int* index);
char* m8(unsigned char* file, int* index);
char* m32(unsigned char* file, int* index); 
char* rm16r32(unsigned char* file, int* index);
char* segment_rm16(unsigned char* file, int* index);
char* rm16r32_segment(unsigned char* file, int* index); 
char* r16r32_rm16r32_imme8(unsigned char* file, int* index); 
char* rm8_imme8(unsigned char* file, int* index);
char* rm16r32_imme16_32(unsigned char* file, int* index); 
char* rm16r32_imme8(unsigned char* file, int* index); 
char* r16r32_rm16r32_imme16_32(unsigned char* file, int* index);
char* rm8_r8(unsigned char* file, int* index); 	//이 함수를 함수포인터로 두자.
char* rm16r32_r16r32(unsigned char* file, int* index); 
char* r8_rm8(unsigned char* file, int* index);
char* r16r32_rm16r32(unsigned char* file, int* index); 
char* imme8(unsigned char* file, int* index); 
char* imme16_32(unsigned char* file, int* index);
char* r16r32_imme16_32(unsigned char* file, int* index); 
char* r16r32_xchg(unsigned char* file, int* index);
char* rel16_32(unsigned char* file, int* index);
/*===================================================================================*/
Elf32_Ehdr elf_header(int file); 
Elf32_Shdr* elf_section_header(Elf32_Ehdr elf, int file); 
struct Symbol_Meta* symbol_table(int strtab_offset, int symtab_offset, int file); 
void check_symtab(int* check_symtab_offset, int e_shnum, Elf32_Shdr* section);
/*===================================================================================*/
//인자 : mnemonic, 함수포인터, file(malloc), num(index)
int parse(char* mnemonic, char*(*func)(unsigned char*, int*), unsigned char* file, int* index); 
//parse와 parse_no는 명령어가 유동적인가, 정해저있는가에 따라 바뀜   
int parse_no(char* mnemonic, unsigned char* file, int* index, int check); 


/*================================*/
int main(int argc, char** argv)
{
	setup(argv[0], argv[1], argc); 
	return 0;
}

void setup(char* binary, char* file_name, int argu_number)
{
	char input_symbol[100]; 
	int fd = open(file_name, O_RDONLY);  //일단 임시로 여기서 열자
	Elf32_Ehdr elf; 
	Elf32_Shdr* section_header; 
	struct Symbol_Meta* symbol_meta; 
	int check_symtab_offset=0, strtab_offset, symtab_offset, i;
   	int symbol_number; 	
	if(argu_number != 2)
	{
		printf("Usage: ./%s <file_name>\n ",binary); 
		exit(1);
	}

	int file_vol; 
	unsigned char* file; 
	file = file_to_heap(file_name, &file_vol); 
	
	elf = elf_header(fd); 
	section_header = elf_section_header(elf, fd); 
	check_symtab(&check_symtab_offset, elf.e_shnum, section_header); //symtab의 위치를 확인 
	
	strtab_offset = ((section_header+elf.e_shstrndx-1)->sh_offset); 
	symtab_offset = (section_header+check_symtab_offset)->sh_offset;
	symbol_number = (strtab_offset - symtab_offset) / 0x10; //struct의 크기만큼 나누어 개수를 확인 
	symbol_meta = symbol_table(strtab_offset, symtab_offset, fd); 
	
	close(fd); 
	//아래코드는 symbol_meta구조체의 내용을 복사한다. 
	copy_symbol_meta.sym_name = (char**)malloc(sizeof(char*)*symbol_number); //해제 필요 
    for(i=0;i<symbol_number;i++)
	{
		copy_symbol_meta.sym_name[i] = (char*)malloc(sizeof(char)*100);  //해제 필요 
	}
	copy_symbol_meta.offset	= (int*)malloc(sizeof(int)*symbol_number);  //해제 필요 

	for(i=0;i<symbol_number;i++)
	{
		strcpy(copy_symbol_meta.sym_name[i], symbol_meta[i].sym_name);
		copy_symbol_meta.offset[i] = symbol_meta[i].offset; 
	}
	copy_symbol_meta.size = symbol_number; 
	
	command_line(file_name, file, file_vol, symbol_meta,symbol_number); 
	free(symbol_meta); 
	free(copy_symbol_meta.offset); 
	for(i=0;i<symbol_number;i++)
	{
		free(copy_symbol_meta.sym_name[i]); 
	}
	free(copy_symbol_meta.sym_name);
	//return 0;

}

char* command_line(char* file_name, unsigned char* file, int file_vol, struct Symbol_Meta* symbol_meta, int symbol_number)
{
	int i; 
	char data[100] = {0, }; 
	char* tok; 
	printf("disassembler v1.0.0\n");
	printf("if you want to help, input : $sd help\n");
	while(1)
	{
		printf("%c[1;31m",27);
		printf("$sd ");
		printf("%c[0m",27);
		fgets(data, sizeof(data), stdin); 
		data[strlen(data)-1] = '\0';
		//read(0, data, sizeof(data)); 
		//printf("%s\n",data);
		if(!strcmp(data, "print symbol"))
		{
			printf("===============================================\n");
			printf("[%s] symbol name\n",file);
			for(i=0;i<symbol_number;i++)
			{
				printf("[%d] : %s\n",i,symbol_meta[i].sym_name);
			} 
			printf("===============================================\n");

		}
		else if(!strncmp(data, "disasm", 6))
		{
			tok = strtok(data, " ");
			tok = strtok(NULL, " "); 
			disasm(file, file_vol, symbol_meta, tok, symbol_number); //number :: symbol 개수 
		}
		else if(!strcmp(data, "quit"))
		{
			exit(1);
		}
		else if(!strcmp(data, "help"))
		{
			printf("\n\n");
			printf("$sd print symbol :: print <%s>'s <symbol_name>\n", file_name); 
			printf("$sd disasm <symbol_name> :: disassembly <symbol_name>\n");
			printf("$sd quit :: quit debugger\n");
			printf("will adding...\n\n");
		}
	}
}

void check_symtab(int* check_symtab_offset, int e_shnum, Elf32_Shdr* section)
{
	int i; 
	for(i=0;i<e_shnum;i++)
	{
		if((section+i)->sh_type == 0x2)
		{
			*check_symtab_offset = i; 
			break; 
		}
	}
	if(!(check_symtab_offset))
	{
		perror("Umm... This is strpped file!"); //이땐 .text부터 분석 시작해보자. 함수의 에필로그와 프롤로그 비교
		exit(1); 
	}
}
//중요구문 call, cmp, test, jmp관련 명령일 때 초록색으로 표시 temp_opcode라고 변수를 선언한 뒤 받자. 
int parse(char* mnemonic, char*(*func)(unsigned char*, int*), unsigned char* file, int* index)
{	
	unsigned char temp_opcode = file[*index]; 
	print_some_address(file, index);
	char ins[256]; 
	memset(ins, '\0', 256); 
	char* show_ins; 

	show_ins = func(file, index); 
	sprintf(ins,mnemonic, show_ins);
	
	/*if(temp_opcode == xxxxx)
	{
		printf("%c[1;31m",27);
		printf("%s",ins);
		printf("%c[0m",27);
	}
	else{
		printf("%s",ins);  
	}*/
	rep_prefix_cat(ins); 
	if((temp_opcode >= 0x70 && temp_opcode <= 0x7f) || (temp_opcode >= 0x80 && temp_opcode <= 0x83) || temp_opcode == 0x84 || temp_opcode == 0x85 || temp_opcode == 0xa8 || temp_opcode == 0xa9 || temp_opcode == 0xc2 ||temp_opcode == 0xc3 || temp_opcode == 0xe8)
	{
		printf("%c[1;32m",27);
		printf("%s",ins);
		printf("%c[0m",27);
	}
	else{
		printf("%s", ins); 
	}

	/*==============전역변수 초기화 구간==========================*/
	segment_override=0;     //0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65
	operand_size=0; 		//0x67
	operand_address=0; 		//0x66
	lock=0;				    //0xf0, 
	rep=0;  				//0xf3
	repn =0;				//0xf2
	check_prefix_line =0;
	byte_ptr = 0;
	dword_ptr = 0;
	word_ptr = 0; 
	two_byte_opcode = 0;    //0x0f
	three_byte_opcode = 0;
	/*===========================================================*/
	free(show_ins);
    return 0;

}
int parse_no(char* mnemonic, unsigned char* file, int* index, int check)
{
	print_some_address(file, index);
	char ins[50] = {0, }; 
	int line = file[*index];//뒤에 3개의 비트를 &7해서 reg값 찾기 
	line = (line) & 0x7; 
	char reg_field[50] = {0, }; 

    if(check){	
		if(operand_size)
		{
			strcpy(reg_field, regs16[line]);
			sprintf(ins ,mnemonic, reg_field);
		}
		else{
			strcpy(reg_field, regs32[line]); 
			sprintf(ins, mnemonic, reg_field);
		}
		rep_prefix_cat(ins);
		printf("%s", ins);
	}
	else{
		rep_prefix_cat(ins);
		printf("%s",mnemonic); 
	}
	/*==============전역변수 초기화 구간==========================*/
	segment_override=0;     //0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65
	operand_size=0; 		//0x67
	operand_address=0; 		//0x66
	lock=0;				    //0xf0, 
	rep=0;  				//0xf3
	repn =0;				//0xf2
	check_prefix_line =0;
	byte_ptr = 0;
	dword_ptr = 0;
	word_ptr =0;
	two_byte_opcode = 0;
	three_byte_opcode = 0;
	/*===========================================================*/
}
/*prefix가 2개 이상인 경우가 있으니 prefix를 읽을 때 마다 check++해서 1일 때만 출력하게 한다. */
void print_some_address(unsigned char* file, int* index)
{
	int i;
	//copy_symbol_meta
	if(check_prefix_line == 1)
	{
		for(i=0;i<copy_symbol_meta.size;i++)
		{
			if(*index == copy_symbol_meta.offset[i])
			{
				printf("\n%08x: <%s>\n\n",*index, copy_symbol_meta.sym_name[i]); 
			}
		}
		some_address = *index; 
		printf("%4x:\t", some_address);
	}
}
/*
본격적으로 바이트 코드를 읽어들임. 80~83까진 reg필드가 명령어를 구분 
*/

/*
일단 모두다 32비트 주소 체계를 따른다고 가정
고려해야할 건 prefix중에 Address는 고려 X 

mod비트를 확인하여 rm이 reg인지 memory인지 확인하자

s비트로 사용하는 레지스터가 8비트인지 16 or 32인지 확인
16 or 32라면 operand_size로 결정 
*/
char* modrm_byte(unsigned char* file, int* index, int modrm, int *mod, int *rm, int *reg, int sbit, int order)
{
	//mod가 0이 아니라면 특정 변수값을 set해서 "+disp]"형태로 갈까 "]" 
	int disp;  //8 or 32
	char rm_field[50];
    char reg_field[50];
	char* final = (char*)malloc(50); 
	memset(final, '\0', 50); 
	memset(reg_field, '\0', 50);	
  	memset(rm_field, '\0', 50); 
	*mod = (modrm >> 6) & 3;
   	*rm = (modrm) & 7;
	*reg = (modrm >> 3) & 7;
	if(*mod == 3){ // rm field is register.
		if(sbit){ //16bit or 32bit
			if(operand_size){ //16
				strcpy(rm_field, regs16[*rm]);
			}
			else{ //32bit
				strcpy(rm_field, regs32[*rm]);
			}
		}
		else{ //8bit
			strcpy(rm_field, regs8[*rm]);
		}
	}
	//disp는 따로 함수를 만들자 
	//disp = mod해서 disp가 있는지(8, 32), 없는지를 구분하자. 
	//char* disp_func() return -> "]" or "+%d]"
	//disp_func과 sib_func에는 rm_field를 순서대로 넘겨 modrm_byte함수에서 시작된 문자열을 
	//disp_func함수에 마무리짓자 
	else{ //rm field is memory addressing
		disp = *mod; //mod = 0(x) mod = 1(disp8) mod = 2(disp32) 
			switch(*rm)
			{
			case 0x0:
				//disp_func(file, index, disp);
				strcpy(rm_field, "[eax"); //%s에는 "]" or "+disp]"이 들어감 
				disp_func(file, index, disp, rm_field);
				break;
			case 0x1:
				strcpy(rm_field, "[ecx"); 
				disp_func(file, index, disp, rm_field);
				break;
			case 0x2:
				strcpy(rm_field, "[edx");
				disp_func(file, index, disp, rm_field);
				break;
			case 0x3:
				strcpy(rm_field, "[ebx");
				disp_func(file, index, disp, rm_field);
				break;
			case 0x4:
				//printf("test11 : %d\n",disp);
				sib_func(file, index, disp, rm_field);
			  	break;	
			case 0x5:
				if(*mod == 0){ //[disp]
					strcpy(rm_field, "[");
					//disp32 == 3
					disp_func(file, index, 3, rm_field);
				}
				else{ //[ebp+disp]
					strcpy(rm_field, "[ebp");
					disp_func(file, index, disp, rm_field);
				}
				break;
			case 0x6:
				strcpy(rm_field,"[esi");
				disp_func(file, index, disp, rm_field);
				break;
			case 0x7:
				strcpy(rm_field, "[edi");
				disp_func(file, index, disp, rm_field);
				break;
			}
	}
	if(sbit){
		if(operand_size){
			strcpy(reg_field, regs16[*reg]);
		}
		else{
			strcpy(reg_field, regs32[*reg]);
		}
	}
	else{
		strcpy(reg_field, regs8[*reg]);
	}
	prefix(rm_field);
	switch(order)
	{
		case 0: //rm_r
			if(byte_ptr && (*mod != 0x3)){ //only memory!!
				memmove(rm_field+9, rm_field, strlen(rm_field));
				memmove(rm_field, "byte ptr ", strlen("byte ptr "));
			}
			else if(dword_ptr && (*mod != 0x3)){
				memmove(rm_field+10, rm_field, strlen(rm_field));
				memmove(rm_field, "dword ptr ", strlen("dword ptr "));
			}
			else if(word_ptr && (*mod != 0x3)){
				memmove(rm_field+9, rm_field, strlen(rm_field));
				memmove(rm_field, "word ptr ", strlen("word ptr "));
			}

			sprintf(final, "%s, %s", rm_field, reg_field);
		   	break;

		case 1: //r_rm
			if(byte_ptr && (*mod != 0x3)){ //only memory!!
				memmove(rm_field+9, rm_field, strlen(rm_field));
				memmove(rm_field, "byte ptr ", strlen("byte ptr "));
			}
			else if(dword_ptr && (*mod != 0x3)){
				memmove(rm_field+10, rm_field, strlen(rm_field));
				memmove(rm_field, "dword ptr ", strlen("dword ptr "));
			}
			else if(word_ptr && (*mod != 0x3)){
				memmove(rm_field+9, rm_field, strlen(rm_field));
				memmove(rm_field, "word ptr ", strlen("word ptr "));
			}
			sprintf(final, "%s, %s", reg_field, rm_field); 
			break; 
		
		case 2: //rm만 있을 경우
			sprintf(final, "%s", rm_field);  
			if(byte_ptr && (*mod != 0x3)){ //only memory!!
				memmove(final+9, final, strlen(final));
				memmove(final, "byte ptr ", strlen("byte ptr "));
			}
			else if(dword_ptr && (*mod != 0x3)){
				memmove(final+10, final, strlen(final));
				memmove(final, "dword ptr ", strlen("dword ptr "));
			}
			else if(word_ptr && (*mod != 0x3)){
				memmove(final+9, final, strlen(final));
				memmove(final, "word ptr ", strlen("word ptr "));
			}
			break;

		case 3: //rm_segment의 경우 
			sprintf(final, "%s, %s",rm_field, mov_segment[*reg]);
			break;

		case 4: //segment_rm일 경우  
			sprintf(final, "%s, %s",mov_segment[*reg], rm_field); 
			break; 
		case 5: //reg만일뿐 
			sprintf(final, "%s", reg_field); 
			break; 
	}
	//여기서 prefix를 붙일것인가? 
	//char* prefix(); 해서 하도록 하자.
	//printf("test8 : %s\n",rm_field);
	return final; 
}

void rep_prefix_cat(char* rm_field)
{
	char rep_prefix[50] = {0, }; 
	if(rep)
	{
		strcpy(rep_prefix, "rep "); 
		strcat(rep_prefix, rm_field);  
		strcpy(rm_field, rep_prefix);
		rep = 0;
	}
	else if(repn)
	{
		strcpy(rep_prefix, "repn ");
		strcat(rep_prefix, rm_field); 
		strcpy(rm_field, rep_prefix); 
		repn = 0;
	}

}
void prefix(char* rm_field)
{
	char segment[50] = {0, }; 
	//memset(segment, '\0', 20); 
	char rep_prefix[50] = {0, }; 

	if(segment_override)
	{
		segment_sprintf(segment);
		strcat(segment, rm_field);
	   	strcpy(rm_field, segment);
		segment_override = 0;
	}
	/*if(rep)
	{
		strcpy(rep_prefix, "rep "); 
		strcat(rep_prefix, rm_field);  
		strcpy(rm_field, rep_prefix);
		rep = 0;
	}
	else if(repn)
	{
		strcpy(rep_prefix, "repn ");
		strcat(rep_prefix, rm_field); 
		strcpy(rm_field, rep_prefix); 
		repn = 0;
	}*/
}
//[sib_base[base]+scale[index]*n        분리             + disp]
void sib_func(unsigned char* file, int* index, int disp, char* sib_field) //sib_base
{
	int n, ss, base, s_index; 
	int sib = file[++(*index)]; 
	ss = (sib >> 6) & 3; 
	base = (sib) & 7; 
	s_index = (sib >> 3) & 7; 
	
	switch(ss)
	{
		case 0x0: n = 1; break;
		case 0x1: n = 2; break; 
		case 0x2: n = 4; break; 
		case 0x3: n = 8; break;
	}
	sprintf(sib_field, "[%s+%s*%d", sib_base[base], scale_index[s_index], n);
	disp_func(file, index, disp, sib_field);
}

void disp_func(unsigned char* file, int* index, int disp, char* disp_field)
{
	int i;
    char temp[50];
	char* hex;
	char complement_disp; //음수체크 
	int complement_disp32; //disp32의 음수체크 
	short complement_disp16; //disp16 check 
	unsigned char disp32[4];
	unsigned char disp16[2]; 
	memset(temp, '\0', 50);
	if(disp == 0){
		strcat(disp_field, "]");
	}
	else if(disp == 1){  //1 byte //disp위치에서 1바이트 읽기 
		disp = file[++(*index)];
		complement_disp = disp;
		if(complement_disp < 0)
		{
			sprintf(temp, "%d]", complement_disp);
			strcat(disp_field, temp); 
		}
	   	else{
			sprintf(temp, "+%d]",complement_disp); 
			strcat(disp_field, temp);	
		}
	}

	else if(disp ==2){   //4 byte //disp위치에서 4바이트 읽기 
		//printf("test1\n");
		for(i=0;i<4;i++){
			disp32[i] = file[++(*index)]; 
		//	printf("test dis32 : %x\n", disp32[i]);
		}
		sprintf(temp, "%02x%02x%02x%02x", disp32[3], disp32[2], disp32[1], disp32[0]); 
		complement_disp32 = strtol(temp, NULL, 16); 
		//printf("test2 : %d\n", complement_disp32);
		//printf("test2 : %s\n", temp);
		memset(temp, '\0', 50);
		if(complement_disp32 < 0)
		{
			sprintf(temp, "%d]", complement_disp32);
			strcat(disp_field, temp); 
			//printf("test4 : %s\n", disp_field); 
		}
		else{
			sprintf(temp, "+%d]", complement_disp32); 
			strcat(disp_field, temp);
			//printf("test3  : %s\n", disp_field);
		}
		//sprintf로 임시로 받고 다시 붙이자 disp_field에 붙여야함. 
	}

    else if(disp == 3){ //
		for(i=0;i<4;i++){
			disp32[i] = file[++(*index)]; 
		}
		sprintf(temp, "0x%02x%02x%02x%02x]", disp32[3], disp32[2], disp32[1], disp32[0]);
		strcat(disp_field, temp);
	}
	else if(disp == 4){
		for(i=0;i<2;i++){
			disp16[i] = file[++(*index)]; 
		}
		sprintf(temp, "%02x%02x", disp16[1], disp16[0]); 
		complement_disp16 = strtol(temp, NULL, 16); 
		memset(temp, '\0', 50); 
		sprintf(temp, "%d", complement_disp16);
		strcat(disp_field, temp); 
	}
}
//점프 관련해서 symbol명 적기 
//그리고 주소 출력할때 옆에 그 주소와 symbol 주소와 일치하면 <symbol name> 넣어주기
//인자를 어떻게 주지... 벌써 너무 많이 써서 힘들듯한데 => 전역변수로 선언 ㅎ 
char* rel16_32(unsigned char* file, int* index)
{
	int check=0;
	int rel32 = *index; 
	int jump_distance, i; 
	int disp32[4] = {0, }; 
	char temp[20] = {0, }; 
	char* final = (char*)malloc(50);
    memset(final, '\0', 50); 	

	for(i=0;i<4;i++){
		disp32[i] = file[++(*index)]; 
	}
	sprintf(temp, "%02x%02x%02x%02x", disp32[3], disp32[2], disp32[1], disp32[0]); 
	jump_distance = strtol(temp, NULL, 16); 
	rel32 = rel32 + 5 + jump_distance; 
	//sprintf(final,"%x",rel32); 
 	for(i=0;i<copy_symbol_meta.size;i++)
	{
		if(rel32 == copy_symbol_meta.offset[i])
		{
			sprintf(final, "%x <%s>",rel32, copy_symbol_meta.sym_name[i]); 
			check = 1;
			break; 
		}
	}
	if(check == 0)
		sprintf(final, "%x", rel32); 
	return final;
}

char* rel8(unsigned char* file, int* index) 
{
	int check=0; 
	int rel8 = *index; 
	char jump_distance = file[++(*index)]; 
	//if(jump_distance >= 0)

	rel8 = rel8 + jump_distance + 2;
    char* final = (char*)malloc(50); 
	memset(final, '\0', 50); 
	//sprintf(final, "%x", rel8);
	//disp_func(file, index, 1, final); 
	//remove_char(final);
	int i;
	for(i=0;i<copy_symbol_meta.size;i++)
	{
		if(rel8 == copy_symbol_meta.offset[i])
		{
			sprintf(final, "%x <%s>",rel8, copy_symbol_meta.sym_name[i]); 
			check = 1; 
			break; 
		}
	}
	if(check == 0)
		sprintf(final, "%x", rel8); 
	return final;	
}

char* r16r32_rm16r32_imme16_32(unsigned char* file, int* index)
{
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 
	order = 1;//rm_r     order = 1 //r_rm
	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, 1, order); 
	strcat(final, ", "); 
	disp_func(file, index, 2, final); 
	remove_char(final); 
	return final; 
}

char* r16r32_rm16r32_imme8(unsigned char* file, int* index)
{
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 
	order = 1;//rm_r     order = 1 //r_rm
	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, 1, order); 
	strcat(final, ", "); 
	disp_func(file, index, 1, final); 
	remove_char(final); 
	return final; 
}

char* imme16_32(unsigned char* file, int* index)
{
	char* imme32_field = (char*)malloc(50);
	memset(imme32_field, '\0', 50);
	disp_func(file, index, 2, imme32_field);
	//printf("test13 : %s\n",imme32_field);
	remove_char(imme32_field);
	return imme32_field;
}

char* r16r32_imme16_32(unsigned char* file, int* index)
{
	unsigned char opcode = file[*index]; 
	opcode = opcode & 7; 
	char* imme_field = (char*)malloc(50); 
	memset(imme_field, '\0', 50);
	if(operand_size){
		sprintf(imme_field, "%s, " ,regs16[opcode]);
		disp_func(file, index, 4, imme_field); 
	}
	else{
		sprintf(imme_field, "%s, " ,regs32[opcode]); 
		disp_func(file, index, 2, imme_field);
		remove_char(imme_field); 
	}
	return imme_field; 
}

char* imme8(unsigned char* file, int* index)
{
	char* imme8_field = (char*)malloc(50);
	memset(imme8_field, '\0', 50);
	disp_func(file, index, 1, imme8_field); 
	remove_char(imme8_field); 
   	return imme8_field; 	
}	

void remove_char(char* str)
{
	for(;*str != '\0';str++)
	{
		if(*str == '+')
		{
			strcpy(str, str+1); 
			str--; 
		}
		else if(*str == ']' && *(str+1) == '\0')
		{
			*str = '\0';
		}
	}
}

char* rm16r32_segment(unsigned char* file, int* index)
{
	int sbit = 1; //mov 0x8c는 sbit값을 고정시켜야함. 
	//int sbit = file[*index] & 1;
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 

	order = 3;//rm_r = 0     order = 1 //r_rm order = 3 //rm_segment

	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	return final; 
}

char* rm16r32(unsigned char* file, int* index)
{
	int sbit = 1; 
	int modrm = file[++(*index)]; 
	int reg, mod, rm, order; 
	char* final; 

	order = 2; //rm만 
	dword_ptr = 1;
	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	return final; 
}

char* rm8(unsigned char* file, int* index)
{
	int sbit = 1;
	int modrm = file[++(*index)]; 
	int reg, mod, rm, order; 
	char* final; 

	order = 2; //rm 
	byte_ptr = 1;
	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	return final; 
}

///////////////////////////////////////////////////////
char* segment_rm16(unsigned char* file, int* index)
{
	int sbit = 1;
	int modrm = file[++(*index)]; 
	int reg, mod, rm, order; 
	char* final; 
	order = 4; //segment_rm; 

	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	return final; 
}

char* m8(unsigned char* file, int* index)
{
	char* field[2] = {"byte ptr es:[edi]", "byte ptr ds:[esi]"}; 
	unsigned char opcode = file[*index]; 
	char* final = (char*)malloc(50);
	memset(final, '\0', 50); 
	if(opcode == 0xa4)
		sprintf(final, "%s, %s", field[0], field[1]);
	else if(opcode == 0xa6)
		sprintf(final, "%s, %s", field[1], field[0]);
	else if(opcode == 0xaa)
		sprintf(final, "%s, al", field[0]); 
	else if(opcode == 0xac)
		sprintf(final, "al, %s",field[1]); 
	else if(opcode == 0xae)
		sprintf(final, "al, %s",field[0]); 
	//prefix(final); 
	return final; 
}

char* m32(unsigned char* file, int* index)
{
	char* field[2] = {"dword ptr es:[edi]", "dword ptr ds:[esi]"};
	unsigned char opcode = file[*index]; 
	char* final = (char*)malloc(50);
	memset(final, '\0', 50); 
	if(opcode == 0xa5)
		sprintf(final, "%s, %s", field[0], field[1]);
	else if(opcode == 0xa7)
		sprintf(final, "%s, %s", field[1], field[0]);
	else if(opcode == 0xab)
		sprintf(final, "%s, eax",field[0]); 
	else if(opcode == 0xad)
		sprintf(final, "eax, %s", field[1]); 
	else if(opcode == 0xaf)
		sprintf(final, "eax, %s", field[0]);
	//prefix(final); 
	return final; 
}

char* r16r32_xchg(unsigned char* file, int* index)
{
	char* xchg_field = (char*)malloc(50); 
	memset(xchg_field, '\0', 50);
	int opcode = file[*index]; 
	opcode = opcode & 0x7; 
	if(operand_size)
	{
		strcpy(xchg_field, regs16[opcode]); 
		strcat(xchg_field, ", ax");
	}
	else{
		strcpy(xchg_field, regs32[opcode]); 
		strcat(xchg_field, ", eax");
	}
	return xchg_field;
}
///////////////////////////////////////////////////
char* rm16r32_imme16_32(unsigned char* file, int* index)
{
	int sbit = file[*index] & 1;
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 
	dword_ptr=1;
	order = 2;//rm_r = 0     order = 1 //r_rm order = 2 //rm 

	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 

	strcat(final, ", "); 
	disp_func(file, index, 2, final);
	remove_char(final);
	return final; 
}
/////////////////////////////////////////////////////
char* rm16r32_imme8(unsigned char* file, int* index)
{
	int sbit = file[*index] & 1;
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 
	dword_ptr=1; 
	order = 2;//rm_r = 0     order = 1 //r_rm order = 2 //rm 

	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 

	strcat(final, ", "); 
	disp_func(file, index, 1, final);
	remove_char(final);
	return final; 
}

char* rm8_imme8(unsigned char* file, int* index)
{
	int sbit = file[*index] & 1;
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 
	byte_ptr =1;
	order = 2;//rm_r = 0     order = 1 //r_rm order = 2 //rm 
	//byte ptr
	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	strcat(final, ", "); 
	disp_func(file, index, 1, final);
	remove_char(final);
	return final; 
	
}
/////////////////////////////////////////////////////
char* r8_rm8(unsigned char* file, int* index)
{
	int sbit = file[*index] & 1;
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 

	order = 1;//rm_r = 0     order = 1 //r_rm

	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	return final; 
}

char* rm8_r8(unsigned char* file, int* index)
{
	int sbit = file[*index] & 1;
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 

	order = 0;//rm_r     order = 1 //r_rm

	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	return final; 
}
char* rm16r32_r16r32(unsigned char* file, int* index)
{
	int sbit = file[*index] & 1;
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 
	dword_ptr = 1;
	order = 0;//rm_r     order = 1 //r_rm

	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	return final; 
}
//////////////////////////////////////////////////////////////////
//메모리일땐 그냥 byte, word, dword로 구분시켜주고
//레지스터일땐 왼쪽, 오른쪽 구분해서 modrm표 보고 넣어주면 될듯한데 
char* r16r32_rm8(unsigned char* file, int* index)
{
	int modrm = file[++(*index)]; 
	int save_index = *index; 
	int reg, mod, rm, order; 
	char* temp1;
    char* temp2; 
	char* final = (char*)malloc(sizeof(char)*50); 
	memset(final, '\0', 50); 	
	//order = 2(rm), order = 5(reg)
	byte_ptr = 1;
	temp1 = modrm_byte(file, index, modrm, &mod, &rm, &reg, 0, 2); //rm 
	temp2 = modrm_byte(file, &save_index, modrm, &mod, &rm, &reg, 1, 5); //reg
	//printf("test code 2 : %s\n", temp1);
	sprintf(final, "%s, %s", temp2, temp1); 
	//printf("test code : %s\n", temp1);
	//free(final2);
	free(temp1); 
	free(temp2);
	return final; 
}

char* r16r32_rm16(unsigned char* file, int* index)
{
	int modrm = file[++(*index)]; 
	int save_index = *index; 
	int reg, mod, rm, order; 
	char* temp1; 
	char* temp2; 
	char* final = (char*)malloc(sizeof(char)*50);
	memset(final, '\0', 50); 
	word_ptr = 1; 
	operand_size = 1;
	temp1 = modrm_byte(file, index, modrm, &mod, &rm, &reg, 1, 2); //rm  
	operand_size = 0;	
	temp2 = modrm_byte(file, &save_index, modrm, &mod, &rm, &reg, 1, 5); //reg 

	//modrm_byte를 두번돌려서 index가 많이 흐트려진다. 
	//그리고 save_index를  선언한뒤 modrm에서 index를 저장하고 
	//다음 modrm_byte를 넘길때 save_index를 넘겨야 한다. 	

	sprintf(final, "%s, %s", temp2, temp1); 
	free(temp1); 
	free(temp2);
	return final; 
}
/////////////////////////////////////////////////////////////////
char* r16r32_rm16r32(unsigned char* file, int* index)
{
	int sbit = file[*index] & 1;
	int modrm = file[++(*index)];
	int reg, mod, rm, order;
	char* final; 

	order = 1;//rm_r     order = 1 //r_rm
	dword_ptr = 1;
	final = modrm_byte(file, index, modrm, &mod, &rm, &reg, sbit, order); 
	return final; 
}
//mov eax, :: gs:0x14 여기서 세그먼트는 segment_override로 찾고 prefix 
char* moffset16_32(unsigned char* file, int* index)
{
	char* segment_field = (char*)malloc(50); 
	char* imme32_field = (char*)malloc(50);
	char* final = (char*)malloc(50);
	memset(final, '\0', 50); 
	memset(segment_field, '\0', 50); 
	memset(imme32_field, '\0', 50);
	disp_func(file, index, 2, imme32_field); 
	remove_char(imme32_field); 
	prefix(segment_field); 

	sprintf(final, "eax, %s%s",segment_field, imme32_field); 
	free(imme32_field); 
	free(segment_field); 
   	return final; 	

}

int disasm(unsigned char* file, int file_vol, struct Symbol_Meta* symbol_meta, char* input_symbol, int symbol_number)
{ 
	
	int save_index; 
	int sym_index, check=0; 
	for(sym_index=0;sym_index<symbol_number;sym_index++)
	{
		if(!strcmp(input_symbol, symbol_meta[sym_index].sym_name))
		{
			check = sym_index;
			break;
		}
	}
	if(check == 0)
	{
		printf("%s symbol isn't exist!\n",input_symbol); 
		return 1;
	}
	int index=symbol_meta[check].offset;
	save_index = index; 
	
	while(index < save_index+symbol_meta[check].size) //file_vol
	{
		check_prefix_line++;
		switch(file[index])
		{ 
			case 0x00: parse("add %s\n", rm8_r8, file, &index); break;
			case 0x01: parse("add %s\n", rm16r32_r16r32, file, &index); break; 
			case 0x02: parse("add %s\n", r8_rm8, file, &index); break;
			case 0x03: parse("add %s\n", r16r32_rm16r32, file, &index); break;  
			case 0x04: parse("add al, %s\n", imme8, file, &index); break; 
			case 0x05: parse("add eax, %s\n", imme16_32, file, &index); break;
			case 0x06: parse_no("push es\n",file, &index,0); break;
			case 0x07: parse_no("pop es\n", file, &index,0); break;
			case 0x08: parse("or %s\n", rm8_r8, file, &index); break; 
			case 0x09: parse("or %s\n", rm16r32_r16r32, file, &index); break;
			case 0x0a: parse("or %s\n", r8_rm8, file, &index); break;
			case 0x0b: parse("or %s\n", r16r32_rm16r32, file, &index); break; 
			case 0x0c: parse("or al %s\n", imme8, file, &index); break;
			case 0x0d: parse("or eax %s\n", imme16_32, file, &index); break; 
			case 0x0e: parse_no("push cs\n", file, &index,0); break; 
			case 0x0f:
			{
				print_some_address(file, &index);
				check_prefix_line++;
				++index;
				switch(file[index])
				{
					case 0x80: parse("jo %s\n", rel16_32, file, &index); break;
					case 0x81: parse("jno %s\n", rel16_32, file, &index); break;
					case 0x82: parse("jb %s\n", rel16_32, file, &index); break;
					case 0x83: parse("jnb %s\n", rel16_32, file, &index); break;
					case 0x84: parse("je %s\n", rel16_32, file, &index); break;
					case 0x85: parse("jne %s\n", rel16_32, file, &index); break;
					case 0x86: parse("jbe %s\n", rel16_32, file, &index); break;
					case 0x87: parse("jnbe %s\n", rel16_32, file, &index); break;
					case 0x88: parse("js %s\n", rel16_32, file, &index); break;
					case 0x89: parse("jns %s\n", rel16_32, file, &index); break;
					case 0x8a: parse("jp %s\n", rel16_32, file, &index); break;
					case 0x8b: parse("jnp %s\n", rel16_32, file, &index); break;
					case 0x8c: parse("jl %s\n", rel16_32, file, &index); break;
					case 0x8d: parse("jnl %s\n", rel16_32, file, &index); break;
					case 0x8e: parse("jle %s\n", rel16_32, file, &index); break;
					case 0x8f: parse("jnle %s\n", rel16_32, file, &index); break;
					case 0x90: parse("seto %s\n", rm8, file, &index); break;
					case 0x91: parse("setno %s\n", rm8, file, &index); break;
					case 0x92: parse("setb %s\n", rm8, file, &index); break;
					case 0x93: parse("setnb %s\n", rm8, file, &index); break;
					case 0x94: parse("setz %s\n", rm8, file, &index); break;
					case 0x95: parse("setnz %s\n", rm8, file, &index); break;
					case 0x96: parse("setbe %s\n", rm8, file, &index); break;
					case 0x97: parse("setnbe %s\n", rm8, file, &index); break;
					case 0x98: parse("sets %s\n", rm8, file, &index); break;
					case 0x99: parse("setns %s\n", rm8, file, &index); break;
					case 0x9a: parse("setp %s\n", rm8, file, &index); break;
					case 0x9b: parse("setnp %s\n", rm8, file, &index); break;							   
					case 0x9c: parse("setl %s\n", rm8, file, &index); break;
					case 0x9d: parse("setnl %s\n", rm8, file, &index); break;
					case 0x9e: parse("setle %s\n", rm8, file, &index); break;
					case 0x9f: parse("setnle %s\n", rm8, file, &index); break;
					case 0xa0: parse_no("push fs\n",file, &index, 0); break; 
					case 0xa1: parse_no("pop fs\n", file, &index, 0); break; 
					case 0xa8: parse_no("push gs\n",file, &index, 0); break; 
					case 0xa9: parse_no("pop gs\n", file, &index, 0); break;  
					case 0xaf: parse("imul %s\n",r16r32_rm16r32, file, &index); break; 
					case 0xb6: parse("movzx %s\n", r16r32_rm8, file, &index); break; 
					case 0xb7: parse("movzx %s\n", r16r32_rm16, file, &index); break; 
					case 0xbe: parse("movsx %s\n", r16r32_rm8, file, &index); break;  
					case 0xbf: parse("movsx %s\n", r16r32_rm16, file, &index); break; 
				}
			} break; 
			case 0x10: parse("adc %s\n", rm8_r8, file, &index); break; 
			case 0x11: parse("adc %s\n", rm16r32_r16r32, file, &index); break;
			case 0x12: parse("adc %s\n", r8_rm8, file, &index); break;
			case 0x13: parse("adc %s\n", r16r32_rm16r32, file, &index); break;
			case 0x14: parse("adc al, %s\n", imme8, file, &index); break;
			case 0x15: parse("adc eax, %s\n", imme16_32, file, &index); break;
			case 0x16: parse_no("push ss\n",file, &index,0); break; 
			case 0x17: parse_no("pop es\n", file, &index,0); break;
			case 0x18: parse("sbb %s\n", rm8_r8, file, &index); break; 
			case 0x19: parse("sbb %s\n", rm16r32_r16r32, file, &index); break;
			case 0x1a: parse("sbb %s\n", r8_rm8, file, &index); break;
			case 0x1b: parse("sbb %s\n", r16r32_rm16r32, file, &index); break;
			case 0x1c: parse("sbb al, %s\n", imme8, file, &index); break;
			case 0x1d: parse("sbb eax, %s\n", imme16_32, file, &index); break;
			case 0x1e: parse_no("push ds\n", file, &index,0); break; 
			case 0x1f: parse_no("pop ds\n", file, &index,0); break;
			case 0x20: parse("and %s\n", rm8_r8, file, &index); break;
			case 0x21: parse("and %s\n", rm16r32_r16r32, file, &index); break;
			case 0x22: parse("and %s\n", r8_rm8, file, &index); break;
			case 0x23: parse("and %s\n", r16r32_rm16r32, file, &index); break;
			case 0x24: parse("and al, %s\n", imme8, file, &index); break;
			case 0x25: parse("and eax, %s\n", imme16_32, file, &index); break;			   
			case 0x26: segment_override=0x26; print_some_address(file, &index);  break;
			case 0x27: parse_no("daa al\n", file, &index,0); break;  
			case 0x28: parse("sub %s\n", rm8_r8, file, &index); break;
			case 0x29: parse("sub %s\n", rm16r32_r16r32, file, &index); break;
			case 0x2a: parse("sub %s\n", r8_rm8, file, &index); break;
			case 0x2b: parse("sub %s\n", r16r32_rm16r32, file, &index); break;
			case 0x2c: parse("sub al, %s\n", imme8, file, &index); break;
			case 0x2d: parse("sub eax, %s\n", imme16_32, file, &index); break;			   
			case 0x2e: segment_override=0x2e; print_some_address(file, &index); break; 
			case 0x2f: parse_no("das al\n", file, &index,0); break;
			case 0x30: parse("xor %s\n", rm8_r8, file, &index); break;
			case 0x31: parse("xor %s\n", rm16r32_r16r32, file, &index); break;
			case 0x32: parse("xor %s\n", r8_rm8, file, &index); break;
			case 0x33: parse("xor %s\n", r16r32_rm16r32, file, &index); break;
			case 0x34: parse("xor al, %s\n", imme8, file, &index); break;
			case 0x35: parse("xor eax, %s\n", imme16_32, file, &index); break;	
			case 0x36: segment_override=0x36; print_some_address(file, &index); break;
			case 0x37: parse_no("aaa al, ah\n", file, &index,0); break;
			case 0x38: parse("cmp %s\n", rm8_r8, file, &index); break;
			case 0x39: parse("cmp %s\n", rm16r32_r16r32, file, &index); break;
			case 0x3a: parse("cmp %s\n", r8_rm8, file, &index); break;
			case 0x3b: parse("cmp %s\n", r16r32_rm16r32, file, &index); break;
			case 0x3c: parse("cmp al, %s\n", imme8, file, &index); break;
			case 0x3d: parse("cmp eax, %s\n", imme16_32, file, &index); break;	
			case 0x3e: segment_override=0x3e; print_some_address(file, &index);  break;
			case 0x3f: parse_no("aas al, ah\n", file, &index,0); break;
		    case 0x40: parse_no("inc %s\n",file, &index,1); break; 
			case 0x41: parse_no("inc %s\n",file, &index,1); break;
			case 0x42: parse_no("inc %s\n",file, &index,1); break;
			case 0x43: parse_no("inc %s\n",file, &index,1); break;
			case 0x44: parse_no("inc %s\n",file, &index,1); break;
			case 0x45: parse_no("inc %s\n",file, &index,1); break;
			case 0x46: parse_no("inc %s\n",file, &index,1); break;
			case 0x47: parse_no("int %s\n",file, &index,1); break;
			case 0x48: parse_no("dec %s\n",file, &index,1); break; 
			case 0x49: parse_no("dec %s\n",file, &index,1); break;
			case 0x4a: parse_no("dec %s\n",file, &index,1); break;
			case 0x4b: parse_no("dec %s\n",file, &index,1); break;
			case 0x4c: parse_no("dec %s\n",file, &index,1); break;
			case 0x4d: parse_no("dec %s\n",file, &index,1); break;
			case 0x4e: parse_no("dec %s\n",file, &index,1); break;
			case 0x4f: parse_no("dec %s\n",file, &index,1); break;
	        case 0x50: parse_no("push %s\n",file, &index,1); break; 
			case 0x51: parse_no("push %s\n",file, &index,1); break;
			case 0x52: parse_no("push %s\n",file, &index,1); break;
			case 0x53: parse_no("push %s\n",file, &index,1); break;
			case 0x54: parse_no("push %s\n",file, &index,1); break;
			case 0x55: parse_no("push %s\n",file, &index,1); break;
			case 0x56: parse_no("push %s\n",file, &index,1); break;
			case 0x57: parse_no("push %s\n",file, &index,1); break;
			case 0x58: parse_no("pop %s\n",file, &index,1); break; 
			case 0x59: parse_no("pop %s\n",file, &index,1); break;
			case 0x5a: parse_no("pop %s\n",file, &index,1); break;
			case 0x5b: parse_no("pop %s\n",file, &index,1); break;
			case 0x5c: parse_no("pop %s\n",file, &index,1); break;
			case 0x5d: parse_no("pop %s\n",file, &index,1); break;
			case 0x5e: parse_no("pop %s\n",file, &index,1); break;
			case 0x5f: parse_no("pop %s\n",file, &index,1); break;
			case 0x60: parse_no("pushad\n", file, &index,0); break;
			case 0x61: parse_no("ppopad\n", file, &index,0); break;
			case 0x62: break;
			case 0x63: break; 
			case 0x64: segment_override=0x64; print_some_address(file, &index);  break;
			case 0x65: segment_override=0x65; print_some_address(file, &index);  break;
			case 0x66: operand_size=1; print_some_address(file, &index);  break; 
			case 0x67: operand_address=1; print_some_address(file, &index); break;
			case 0x68: parse("push %s\n", imme16_32, file, &index); break;
			case 0x69: parse("imul %s\n", r16r32_rm16r32_imme16_32, file, &index); break; 
			case 0x6a: parse("push %s\n", imme8, file, &index); break;
			case 0x6b: parse("imul %s\n", r16r32_rm16r32_imme8, file, &index); break;
			case 0x6c: break; 
			case 0x6d: break; 
			case 0x6e: break; 
			case 0x70: parse("jo %s\n", rel8, file, &index); break;
			case 0x71: parse("jno %s\n", rel8, file, &index); break;
			case 0x72: parse("jb %s\n", rel8, file, &index); break;
			case 0x73: parse("jnb %s\n", rel8, file, &index); break;
			case 0x74: parse("je %s\n", rel8, file, &index); break;
			case 0x75: parse("jne %s\n", rel8, file, &index); break;
			case 0x76: parse("jbe %s\n", rel8, file, &index); break;
			case 0x77: parse("jnbe %s\n", rel8, file, &index); break;
			case 0x78: parse("js %s\n", rel8, file, &index); break;
			case 0x79: parse("jns %s\n", rel8, file, &index); break;
			case 0x7a: parse("jp %s\n", rel8, file, &index); break;
			case 0x7b: parse("jnp %s\n", rel8, file, &index); break;
			case 0x7c: parse("jl %s\n", rel8, file, &index); break;
			case 0x7d: parse("jnl %s\n", rel8, file, &index); break;
			case 0x7e: parse("jle %s\n", rel8, file, &index); break;
			case 0x7f: parse("jnle %s\n", rel8, file, &index); break;
			case 0x80:
			{
				int reg, opcode = file[++(index)];
				index--;
				reg = (opcode >> 3) & 7; 
				//printf("test19 : %d\n", reg);
				switch(reg)
				{
					case 0x00: parse("add %s\n", rm8_imme8, file, &index); break;
					case 0x01: parse("or %s\n", rm8_imme8, file, &index); break;
					case 0x02: parse("adc %s\n", rm8_imme8, file, &index); break;
					case 0x03: parse("sbb %s\n", rm8_imme8, file, &index); break;
					case 0x04: parse("and %s\n", rm8_imme8, file, &index); break;
					case 0x05: parse("sub %s\n", rm8_imme8, file, &index); break;
					case 0x06: parse("xor %s\n", rm8_imme8, file, &index); break;
					case 0x07: parse("cmp %s\n", rm8_imme8, file, &index); break;
				}
			} break;
			case 0x81:
			{
				int reg, opcode = file[++(index)];
				index--;
				reg = (opcode >> 3) & 7; 
				//printf("test19 : %d\n", reg);
				switch(reg)
				{
					case 0x00: parse("add %s\n", rm16r32_imme16_32, file, &index); break;
					case 0x01: parse("or %s\n", rm16r32_imme16_32, file, &index); break;
					case 0x02: parse("adc %s\n", rm16r32_imme16_32, file, &index); break;
					case 0x03: parse("sbb %s\n", rm16r32_imme16_32, file, &index); break;
					case 0x04: parse("and %s\n", rm16r32_imme16_32, file, &index); break;
					case 0x05: parse("sub %s\n", rm16r32_imme16_32, file, &index); break;
					case 0x06: parse("xor %s\n", rm16r32_imme16_32, file, &index); break;
					case 0x07: parse("cmp %s\n", rm16r32_imme16_32, file, &index); break;
				}
			} break;	
			case 0x82:
			{
				int reg, opcode = file[++(index)];
				index--;
				reg = (opcode >> 3) & 7; 
				//printf("test19 : %d\n", reg);
				switch(reg)
				{
					case 0x00: parse("add %s\n", rm8_imme8, file, &index); break;
					case 0x01: parse("or %s\n", rm8_imme8, file, &index); break;
					case 0x02: parse("adc %s\n", rm8_imme8, file, &index); break;
					case 0x03: parse("sbb %s\n", rm8_imme8, file, &index); break;
					case 0x04: parse("and %s\n", rm8_imme8, file, &index); break;
					case 0x05: parse("sub %s\n", rm8_imme8, file, &index); break;
					case 0x06: parse("xor %s\n", rm8_imme8, file, &index); break;
					case 0x07: parse("cmp %s\n", rm8_imme8, file, &index); break;
				}
			} break; 
			case 0x83:
			{
				int reg, opcode = file[++(index)];
				index--;
				reg = (opcode >> 3) & 7; 
				//printf("test19 : %d\n", reg);
				switch(reg)
				{
					case 0x00: parse("add %s\n", rm16r32_imme8, file, &index); break; // byte 붙이자. 
					case 0x01: parse("or %s\n", rm16r32_imme8, file, &index); break;
					case 0x02: parse("adc %s\n", rm16r32_imme8, file, &index); break;
					case 0x03: parse("sbb %s\n", rm16r32_imme8, file, &index); break;
					case 0x04: parse("and %s\n", rm16r32_imme8, file, &index); break;
					case 0x05: parse("sub %s\n", rm16r32_imme8, file, &index); break;
					case 0x06: parse("xor %s\n", rm16r32_imme8, file, &index); break;
					case 0x07: parse("cmp %s\n", rm16r32_imme8, file, &index); break;
				}
			} break; 
			case 0x84: parse("test %s\n", rm8_r8, file, &index); break;
			case 0x85: parse("test %s\n", rm16r32_r16r32, file, &index); break; 
			case 0x86: parse("xchg %s\n", r8_rm8, file, &index); break; 
			case 0x87: parse("xchg %s\n", r16r32_rm16r32, file, &index); break;
			case 0x88: parse("mov %s\n", rm8_r8, file, &index); break;
			case 0x89: parse("mov %s\n", rm16r32_r16r32, file, &index); break; 
			case 0x8a: parse("mov %s\n", r8_rm8, file, &index); break;
			case 0x8b: parse("mov %s\n", r16r32_rm16r32, file, &index); break;  
			case 0x8c: parse("mov %s\n", rm16r32_segment, file, &index); break; 
			case 0x8d: parse("lea %s\n", r16r32_rm16r32, file, &index); break; 
			case 0x8e: parse("mov %s\n", segment_rm16, file, &index); break;
			case 0x8f: parse("pop %s\n", rm16r32, file, &index); break;  
			case 0x90: parse_no("nop\n", file, &index, 0); break; 
			case 0x91: parse("xchg %s\n",r16r32_xchg, file, &index); break; //뒤에 3비트를 7과 &연산하자. 
			case 0x92: parse("xchg %s\n",r16r32_xchg, file, &index); break;
			case 0x93: parse("xchg %s\n",r16r32_xchg, file, &index); break;
			case 0x94: parse("xchg %s\n",r16r32_xchg, file, &index); break;
			case 0x95: parse("xchg %s\n",r16r32_xchg, file, &index); break;
			case 0x96: parse("xchg %s\n",r16r32_xchg, file, &index); break;
			case 0x97: parse("xchg %s\n",r16r32_xchg, file, &index); break;
			case 0x98: parse_no("cwde\n", file, &index,1); break;
			case 0x99: parse_no("cdq\n", file, &index,1); break; 
			case 0xa1: parse("mov %s\n", moffset16_32, file, &index); break; 
			case 0xa4: parse("movsb %s\n", m8, file, &index); break;
			case 0xa5: parse("movsd %s\n", m32, file, &index); break; 
			case 0xa6: parse("cmpsb %s\n", m8, file, &index); break; 
			case 0xa7: parse("cmpsd %s\n", m32, file, &index); break;
			case 0xa8: parse("test al %s\n", imme8, file, &index); break; 
			case 0xa9: parse("test eax %s\n", imme16_32, file, &index); break;
			case 0xaa: parse("stosb %s\n", m8, file, &index); break; 
			case 0xab: parse("stosd %s\n", m32, file, &index); break; 
			case 0xac: parse("lodsb %s\n", m8, file, &index); break; 
			case 0xad: parse("lodsd %s\n", m32, file, &index); break; 
			case 0xae: parse("scasb %s\n", m8, file, &index); break; 
			case 0xaf: parse("scasd %s\n", m32, file, &index); break; 
			case 0xb0: parse("mov al %s\n", imme8, file, &index); break; 
			case 0xb1: parse("mov cl %s\n", imme8, file, &index); break;
			case 0xb2: parse("mov dl %s\n", imme8, file, &index); break;
			case 0xb3: parse("mov bl %s\n", imme8, file, &index); break;
			case 0xb4: parse("mov ah %s\n", imme8, file, &index); break;
			case 0xb5: parse("mov ch %s\n", imme8, file, &index); break;
			case 0xb6: parse("mov dh %s\n", imme8, file, &index); break;
			case 0xb7: parse("mov bh %s\n", imme8, file, &index); break;
			case 0xb8: parse("mov %s\n", r16r32_imme16_32, file, &index); break;
			case 0xb9: parse("mov %s\n", r16r32_imme16_32, file, &index); break;
			case 0xba: parse("mov %s\n", r16r32_imme16_32, file, &index); break;
			case 0xbb: parse("mov %s\n", r16r32_imme16_32, file, &index); break;
			case 0xbc: parse("mov %s\n", r16r32_imme16_32, file, &index); break;
			case 0xbd: parse("mov %s\n", r16r32_imme16_32, file, &index); break;
			case 0xbe: parse("mov %s\n", r16r32_imme16_32, file, &index); break;
			case 0xbf: parse("mov %s\n", r16r32_imme16_32, file, &index); break;
			case 0xc0: 
			{
				int reg = (file[(++index)] >> 3) & 7; 
				index--; 
				switch(reg)
				{
					case 0x00: parse("rol %s\n", rm8_imme8, file, &index); break;
					case 0x01: parse("ror %s\n", rm8_imme8, file, &index); break;
					case 0x02: parse("rcl %s\n", rm8_imme8, file, &index); break;
					case 0x03: parse("rcr %s\n", rm8_imme8, file, &index); break;
					case 0x04: parse("shl %s\n", rm8_imme8, file, &index); break;
					case 0x05: parse("shr %s\n", rm8_imme8, file, &index); break;
					case 0x06: parse("sal %s\n", rm8_imme8, file, &index); break;
					case 0x07: parse("sar %s\n", rm8_imme8, file, &index); break;

				}
			} break;
			case 0xc1:
			{
				int reg = (file[++index] >> 3) & 7; 
				index--; 
				switch(reg)
				{

					case 0x00: parse("rol %s\n", rm16r32_imme8, file, &index); break;
					case 0x01: parse("ror %s\n", rm16r32_imme8, file, &index); break;
					case 0x02: parse("rcl %s\n", rm16r32_imme8, file, &index); break;
					case 0x03: parse("rcr %s\n", rm16r32_imme8, file, &index); break;
					case 0x04: parse("shl %s\n", rm16r32_imme8, file, &index); break;
					case 0x05: parse("shr %s\n", rm16r32_imme8, file, &index); break;
					case 0x06: parse("sal %s\n", rm16r32_imme8, file, &index); break;
					case 0x07: parse("sar %s\n", rm16r32_imme8, file, &index); break;
				}
			} break;
			case 0xc2: parse_no("ret\n", file, &index, 0); break;	
			case 0xc3: parse_no("ret\n", file, &index, 0); break;
			case 0xc4:
			case 0xc5:
			case 0xc6: parse("mov %s\n",rm8_imme8, file, &index); break;	   
			case 0xc7: parse("mov %s\n", rm16r32_imme16_32, file, &index); break;
			//case 0xc8: parse("enter %s\n", imme16_imme8, file, &index); break; 
			case 0xc9: parse_no("leave\n", file, &index, 0); break; 
			case 0xca: 
			case 0xcb: 
			case 0xcc: parse_no("int 3\n", file, &index, 0); break; 
			case 0xcd: parse("int %s\n", imme8, file, &index); break; //여기서 imme8은 unsigned char임. 
			case 0xce: parse_no("into\n", file, &index, 0); break;
			case 0xcf: parse_no("iretd\n", file, &index, 0); break; 
			case 0xd0:
			{
				int reg = file[++index]; 
				index--; 
				switch(reg)
				{
					case 0x00: parse("rol %s, 1\n",rm8, file, &index); break; 
					case 0x01: parse("ror %s, 1\n",rm8, file, &index); break;
					case 0x02: parse("rcl %s, 1\n",rm8, file, &index); break;
					case 0x03: parse("rcr %s, 1\n",rm8, file, &index); break;
					case 0x04: parse("shl %s, 1\n",rm8, file, &index); break;
					case 0x05: parse("shr %s, 1\n",rm8, file, &index); break;
					case 0x06: parse("sal %s, 1\n",rm8, file, &index); break;
					case 0x07: parse("sar %s, 1\n",rm8, file, &index); break;
				}
			} break;
			case 0xd1:
			{
				int reg = file[++index]; 
				index--; 
				switch(reg)
				{
					case 0x00: parse("rol %s, 1\n",rm16r32, file, &index); break; 
					case 0x01: parse("ror %s, 1\n",rm16r32, file, &index); break;
					case 0x02: parse("rcl %s, 1\n",rm16r32, file, &index); break;
					case 0x03: parse("rcr %s, 1\n",rm16r32, file, &index); break;
					case 0x04: parse("shl %s, 1\n",rm16r32, file, &index); break;
					case 0x05: parse("shr %s, 1\n",rm16r32, file, &index); break;
					case 0x06: parse("sal %s, 1\n",rm16r32, file, &index); break;
					case 0x07: parse("sar %s, 1\n",rm16r32, file, &index); break;
				}
			} break; 

			case 0xd2:
			{
				int reg = file[++index]; 
				index--; 
				switch(reg)
				{
					case 0x00: parse("rol %s, cl\n",rm8, file, &index); break; 
					case 0x01: parse("ror %s, cl\n",rm8, file, &index); break;
					case 0x02: parse("rcl %s, cl\n",rm8, file, &index); break;
					case 0x03: parse("rcr %s, cl\n",rm8, file, &index); break;
					case 0x04: parse("shl %s, cl\n",rm8, file, &index); break;
					case 0x05: parse("shr %s, cl\n",rm8, file, &index); break;
					case 0x06: parse("sal %s, cl\n",rm8, file, &index); break;
					case 0x07: parse("sar %s, cl\n",rm8, file, &index); break;
				}
			} break; 

			case 0xd3:
			{
				int reg = file[++index]; 
				index--; 
				switch(reg)
				{
					case 0x00: parse("rol %s, cl\n",rm16r32, file, &index); break; 
					case 0x01: parse("ror %s, cl\n",rm16r32, file, &index); break;
					case 0x02: parse("rcl %s, cl\n",rm16r32, file, &index); break;
					case 0x03: parse("rcr %s, cl\n",rm16r32, file, &index); break;
					case 0x04: parse("shl %s, cl\n",rm16r32, file, &index); break;
					case 0x05: parse("shr %s, cl\n",rm16r32, file, &index); break;
					case 0x06: parse("sal %s, cl\n",rm16r32, file, &index); break;
					case 0x07: parse("sar %s, cl\n",rm16r32, file, &index); break;
				}
			} break; 
			case 0xd4:
			case 0xd5:

			case 0xe0: parse("loopne %s\n", rel8, file, &index); break;
			case 0xe1: parse("loope %s\n", rel8, file, &index); break; 
			case 0xe2: parse("loop %s\n", rel8, file, &index); break; 
			case 0xe3: 
			case 0xe4:
			case 0xe5:
			case 0xe6:
			case 0xe7: 
			case 0xe8: parse("call %s\n", rel16_32, file, &index); break; 
			case 0xe9: parse("jmp %s\n", rel16_32, file, &index); break; 
			case 0xea:
			case 0xeb: parse("jmp %s\n", rel8, file, &index); break; 
			case 0xec:
			case 0xed:
			case 0xef: 
			case 0xf0: //lock 
			case 0xf1: 		   
			case 0xf2: repn=1; print_some_address(file, &index);  break;
			case 0xf3: rep=1; print_some_address(file, &index); break;
			case 0xf4: parse_no("hlt", file, &index, 0); break;
			case 0xf8: parse_no("clc\n", file, &index, 0); break; 
			case 0xf9: parse_no("stc\n", file, &index, 0); break; 
			case 0xfa: parse_no("cli\n", file, &index, 0); break; 
			case 0xfb: parse_no("sti\n", file, &index, 0); break; 
			case 0xfc: parse_no("cld\n", file, &index, 0); break; 
			case 0xfd: parse_no("std\n", file, &index, 0); break;
			case 0xfe:
			{
				int reg = (file[++index] >> 3) & 7;
				index--;
			    switch(reg)
				{
					case 0x00: parse("inc %s\n", rm8, file, &index); break; 
					case 0x01: parse("dec %s\n", rm8, file, &index); break; 
				}
			}; break; 
			case 0xff:
		  	{
				int reg = (file[++index] >> 3) & 7;
				index--;
			   	switch(reg)
				{
					case 0x00: parse("inc %s\n", rm16r32, file, &index); break; 
					case 0x01: parse("dec %s\n", rm16r32, file, &index); break;
					case 0x02: parse("call %s\n", rm16r32, file, &index); break;
					//case 0x03: parse("callf %s\n", rm16r32, file, &index); break;
					case 0x04: parse("jmp %s\n", rm16r32, file, &index); break;
					//case 0x05: parse("jmpf %s\n", rm16r32, file, &index); break;
					case 0x06: parse("push %s\n", rm16r32, file, &index); break;
				}	
			}; break; 	
			defult: exit(1); 
		}
		index++;
		//printf("test6 index : %x %x\n", index, file[index]);
	}
	return 0;
}
void segment_sprintf(char* segment)
{
	switch(segment_override) //prefix중에 segment_override가 있을 시 
	{
		case 0x2e:
			sprintf(segment, "%s:" ,segreg[0]); 
			break;
		case 0x36:
			sprintf(segment,"%s:", segreg[1]); 
			break;
		case 0x3e:
			sprintf(segment,"%s:", segreg[2]); 
			break;
		case 0x26: 
			sprintf(segment,"%s:", segreg[3]);
			break;
		case 0x64:
			sprintf(segment,"%s:", segreg[4]);
			break;
		case 0x65:
			sprintf(segment,"%s:", segreg[5]);
			break;
		defult:
			break;	
	}
}


/*
 파일의 내용을 동적할당하여 Heap영역에 넣음
*/
char* file_to_heap(char* name, int* file_vol)
{
	int elf;
	int fd;
	unsigned char* file; 
	fd = open(name, O_RDONLY); 
	if(fd <= 0){
		perror("Error"); 
		exit(1);
	}
	elf = check_elf(fd); 
	if(elf)
	{
		printf("This is not ELF\n");
		exit(1);
	}
	*file_vol = lseek(fd, 0, SEEK_END); 
	
	file = (unsigned char*)malloc(sizeof(unsigned char)*(*file_vol));
	if(file == NULL)
	{
		perror("Error");
		exit(1);
	}
	lseek(fd, 0, SEEK_SET);
	read(fd, file, *file_vol);
	close(fd); 
	return file;
}
//동적활당한 이차원 배열을 반환해야함. 
char** elf_parsing(int file)
{
	char** symbol_name = (char**)malloc(sizeof(char*)*3000); 
	int i; 
	for(i=0;i<3000;i++)
		symbol_name[i] = (char*)malloc(sizeof(char)*100); 
	Elf32_Ehdr elf; 
	Elf32_Shdr* section_header; 
	Elf32_Sym* symbol; 

	elf = elf_header(file); 
	section_header = elf_section_header(elf, file); 
	
}

Elf32_Ehdr elf_header(int file)
{
	Elf32_Ehdr elf32; 
	ssize_t check; 
	int i; 
	lseek(file, 0, SEEK_SET);
	read(file, &elf32, sizeof(elf32)); 
	return elf32; 
}

Elf32_Shdr* elf_section_header(Elf32_Ehdr elf, int file)
{
	int i, j; 
	Elf32_Shdr* section_header = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr) * elf.e_shnum); 
	lseek(file, elf.e_shoff,SEEK_SET);

	for(i=0;i<elf.e_shnum;i++)
		read(file, &section_header[i], sizeof(Elf32_Shdr)); 

	return section_header; 
}

struct Symbol_Meta* symbol_table(int strtab_offset, int symtab_offset, int file)
{
	//struct Symbol_Meta* symbol_meta; 

	char name; 
	int size = (strtab_offset - symtab_offset) / 0x10;  //symbol의 개수 
	struct Symbol_Meta* symbol_meta = (struct Symbol_Meta*)malloc(sizeof(struct Symbol_Meta) * size); 
	Elf32_Sym* symbol = (Elf32_Sym*)malloc(sizeof(Elf32_Sym)*size); 
	
	int i, j=0; 

	lseek(file, symtab_offset, SEEK_SET); 
	for(i=0;i<size;i++)
		read(file, &symbol[i], sizeof(Elf32_Sym)); 

	for(i=0;i<size;i++)	{
		symbol_meta[i].offset = symbol[i].st_value;  //symbol offset 
		symbol_meta[i].size = symbol[i].st_size;  //symbol_size 
	}
	for(i=0;i<size;i++)
	{
		lseek(file, strtab_offset+symbol[i].st_name, SEEK_SET); 
		while(read(file, &name, 1))
		{
			if(name == '\0')
				break; 
			symbol_meta[i].sym_name[j] = name; 
			j++;
		}
		symbol_meta[i].sym_name[j] = '\0'; 
		j=0;
	}
	free(symbol); 
	return symbol_meta; 
}

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

