#include <elf.h>

/*
//#include <sys/elf.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <ctype.h>
#include <linux/types.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <assert.h>
*/
typedef struct Instruction_List{
	char ins[50]; 
	unsigned addr; 
	int line_number; 
	struct Instruction_List* next;
	/*unsigned char jump_code;*/
}ins_list; 

typedef struct BreakPoint{
	void* addr; 
	long orig_code; 
	//long orig_code; 
	struct BreakPoint* next;
}breakpoint; 

typedef struct Declares{
	char name[20]; 
	unsigned addr;
	struct Declares* next; 
}declare;

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

typedef void* target_addr_t;

/*===================================================================================*/
void input_declare(char* name, unsigned addr); 
//void delete_declare(); 

/*============Fuction================================================================*/
//void command_line(); 
int print_function(); 
int setup(char* binary, char* file_name, int argu_number); 
char* command_line(pid_t pid, char* file_name, unsigned char* file, int file_vol, struct Symbol_Meta* symbol_meta, int symbol_number, breakpoint* head_bp, int text_offset, int text_size);
int print_some_address(unsigned char* file, int* index);
void sib_func(unsigned char* file, int* index, int disp, char* sib_field);
void disp_func(unsigned char* file, int* index, int disp, char* disp_field);
void segment_sprintf(char* segment);	//세그먼트 레지스터를 넣을 문자열을 설정해줌   
char* file_to_heap(char* name, int* file_vol); 
int disasm(unsigned char* file, int file_vol, struct Symbol_Meta* symbol_meta,  char* input_symbol, int symbol_number, int text_offset, int text_size);
void remove_char(char* str);
char* dec_to_hex(int decimal);
void prefix(char* rm_field); //이 함수안에서 segment_sprintf를 호출하자. 
void rep_prefix_cat(char* rm_field);
int check_elf(int file); 
void print_instruction(char* ins, unsigned char opcode, int line_number);
void ins_add(char* string, unsigned addr, int line_number);
int ins_delete(); 
void print_ins();
int child_ptrace(const char* program_name);
int run_debugger(pid_t pid, const char* program_name); 
void show_information(pid_t pid, ins_list* ins); 
void info_register(pid_t pid);
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
Elf32_Shdr* elf_section_header(Elf32_Ehdr elf, int file, int* text_offset, int* text_size); 
//program header에서 LOAD값을 뽑는 함수 필요 
int elf_program_header_load(Elf32_Ehdr elf, int file); 
struct Symbol_Meta* symbol_table(int strtab_offset, int symtab_offset, int file, int program_virtual_memory_address); 
void check_symtab(int* check_symtab_offset, int e_shnum, Elf32_Shdr* section);
/*===================================================================================*/
//인자 : mnemonic, 함수포인터, file(malloc), num(index)
int parse(char* mnemonic, char*(*func)(unsigned char*, int*), unsigned char* file, int* index); 
//parse와 parse_no는 명령어가 유동적인가, 정해저있는가에 따라 바뀜   
int parse_no(char* mnemonic, unsigned char* file, int* index, int check); 

/*function*/
//int child_ptrace(const char* program_name); 
//int run_debugger(pid_t pid, const char* program_name); 
int create_breakpoint(pid_t pid, breakpoint* head_bp, target_addr_t addr);  
int enable_breakpoint(pid_t pid, breakpoint* bp); 
int delete_breakpoint(pid_t pid, breakpoint* head_bp, int index);
int disable_breakpoint(pid_t pid, breakpoint* head_bp, int index); 
void print_breakpoint(pid_t pid, breakpoint* head_bp); 
//void command_line(pid_t pid, breakpoint* head_bp); 
int run_instruction(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins);
int cont_instruction(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins);
int step_over(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins); 
int step_into(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins); 
//void show_infomation(pid_t pid, breakpoint* head_bp); 
void dump_process_memory(pid_t pid, unsigned from_addr, unsigned size);
void inject_process_memory(pid_t pid, unsigned from_addr, unsigned data, unsigned data_size);
void set_register(pid_t pid, char* regis, unsigned data);
void payload_inject(pid_t pid, unsigned addr, char* buffer, unsigned size);
//void register_info(pid_t pid); 

