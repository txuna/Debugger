#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>
#include <sys/user.h>

#include "dumpcode.h"
#include "debug.h"

/*define value*/
#define TRAP_MASK 0xFFFFFF00
#define TRAP_INST 0xCC

#define fourSwap(X) ((X>>24)&0xff) | ((X<<8)&0xff0000) | ((X>>8)&0xff00) | ((X<<24)&0xff000000) 

#define twoSwap(X) (X>>8) | (X<<8)

//typedef void* target_addr_t; 
/*
typedef struct BreakPoint{
	target_addr_t addr; 
	long orig_code;
    struct BreakPoint* next; //다음 bp 구조체의 주소를 담음. 	
}breakpoint;
*/
//int break_index = 0; 


/*기준 노드가 되는 head_bp는 사용되지 않고 단지 시작점을 잡기 위해 사용됨*/

/*function*/
//int child_ptrace(const char* program_name); 
//int run_debugger(pid_t pid, const char* program_name); 
/*
int create_breakpoint(pid_t pid, breakpoint* head_bp, target_addr_t addr);  
int enable_breakpoint(pid_t pid, breakpoint* bp); 
int delete_breakpoint(pid_t pid, breakpoint* head_bp, int index);
int disable_breakpoint(pid_t pid, breakpoint* head_bp, int index); 
void print_breakpoint(pid_t pid, breakpoint* head_bp); 
//void command_line(pid_t pid, breakpoint* head_bp); 
int run_instruction(pid_t pid, breakpoint* head_bp, int* run_bit);
int cont_instruction(pid_t pid, breakpoint* head_bp, int* run_bit);
int step_over(pid_t pid, breakpoint* head_bp, int* run_bit); 
int step_into(pid_t pid, breakpoint* head_bp, int* run_bit); 
//void show_infomation(pid_t pid, breakpoint* head_bp); 
void dump_process_memory(pid_t pid, unsigned from_addr, unsigned size);
void inject_process_memory(pid_t pid, unsigned from_addr, unsigned data);
void set_register(pid_t pid, char* regis, unsigned data);
//void register_info(pid_t pid); 
void debug_module(pid_t pid, char* command, ins_list* head_ins); //ptrace_traceme를 시전 


void debug_module(pid_t pid, char* command, ins_list* head_ins)
{

}
*/
/*
int main(int argc, char** argv)
{
	//printf("asd");
	if(argc != 2)
	{
		perror("argc!");
		exit(1);
	}

	pid_t child_pid = fork(); 
	if(child_pid  == 0)
		child_ptrace(argv[1]);
	else if(child_pid > 0)
		run_debugger(child_pid, argv[1]); 
	else{
		perror("fork()"); 
		exit(1); 
	}

	return 0; 
}
*/
void set_register(pid_t pid, char* regis, unsigned data)
{
	struct user_regs_struct regs; 
	ptrace(PTRACE_GETREGS, pid, 0, &regs); 
	if(!strcmp(regis, "eax"))
	{
		regs.eax = data; 	
	}
	else if(!strcmp(regis, "ebx"))
	{
		regs.ebx = data; 
	}
	else if(!strcmp(regis, "ecx"))
	{
		regs.ecx = data; 
	}
	else if(!strcmp(regis, "edx"))
	{
		regs.edx = data; 
	}
	else if(!strcmp(regis, "esi"))
	{
		regs.esi = data; 
	}
	else if(!strcmp(regis, "edi"))
	{
		regs.edi = data;
	}
	else if(!strcmp(regis, "ebp"))
	{
		regs.ebp = data; 
	}
	else if(!strcmp(regis, "esp"))
	{
		regs.esp = data;
	}
	else if(!strcmp(regis, "eip"))
	{
		regs.eip = data; 
	}
	else{
		printf("%s register isn't exited\n",regis); 
		//return -1; 
	}
	ptrace(PTRACE_SETREGS, pid, 0, &regs); 
}

int disable_breakpoint(pid_t pid, breakpoint* head_bp, int index) //여기서 처음부터 index받자 
{
	//int index; //temp
	//여기서 opcode 되돌리고 delete_breakpoint함수 호출 
	delete_breakpoint(pid, head_bp, index);
	//PTRACE_SINGLESTEIP
	//PTRACE_CONT  

	return 0;

}
//command info breakpoint => index로 보여줌 

void print_breakpoint(pid_t pid, breakpoint* head_bp)
{
	int i=0;
	breakpoint* curr = head_bp->next; 
	printf("\n[information : breakpoint]\n");
	while( curr !=	NULL) //curr이 NULL일떄까지 
	{
		printf("[%d] %p\n",i, curr->addr); 
		i++; 
		curr = curr->next; 
	}
	printf("\n");
}

int delete_breakpoint(pid_t pid, breakpoint* head_bp, int index)
{
   	//index만큼 while을 돌림. 돌리고 해당 index에 주소가 있는지 없는지 확인함. 
	//허용되지 않은 주소 범위일땐 ptrace error뜨네 그럼, create하기 전에 허용된 주소 인지 아닌지 검사필요
	breakpoint* curr = (breakpoint*)head_bp->next; 
	breakpoint* before = head_bp;
	int i; 
	if(curr == NULL)
	{
		perror("breakpoint (null pointer errro)"); 
		return -1; 
	}
	for(i=0;i,i<index;i++)
	{	before = curr; 
		curr = (breakpoint*)curr->next; 
		if(curr == NULL)
		{
			perror("not breakpoint index (null pointer error)"); 
			return -1;
		}
	}
	before->next = curr->next; 
	
	assert(curr->addr); //check null error; 
   	unsigned data = ptrace(PTRACE_PEEKTEXT, pid, curr->addr, 0); 
	assert((data & 0xFF) == 0xCC); 
	ptrace(PTRACE_POKETEXT, pid, curr->addr, (data & TRAP_MASK) | (curr->orig_code & 0xFF)); 	
    free(curr); 	
	return 0;
}
/*
void show_infomation(pid_t pid, breakpoint* head_bp) 
{	
	int i, j;
   	unsigned data;
	struct user_regs_struct regs; 
	system("clear");
	ptrace(PTRACE_GETREGS, pid, 0, &regs); 
	printf("[--------------------register--------------------]\n"); 
	printf("EAX: 0x%lX\n", regs.eax); //만약 레지스터에 주소값처럼 되어있으면 거기 dump뜬것도 보여주자. 
 	printf("EBX: 0x%lX\n", regs.ebx);
	printf("ECX: 0x%lX\n", regs.ecx);
	printf("EDX: 0x%lX\n", regs.edx); 
	printf("ESI: 0x%lX\n", regs.esi);
	printf("EDI: 0x%lX\n", regs.edi);
	printf("EBP: 0x%lX\n", regs.ebp); 
	printf("ESP: 0x%lX\n", regs.esp); 
	printf("EIP: 0x%lX\n", regs.eip); 
	//printf("EFLAGS:\n"); //
	printf("[----------------------code----------------------]\n");	
	//printf(""); //disassembler.c 에서 선언한 전역변수를 끌고오자. code를 보여줌. 
	printf("[----------------------stack---------------------]\n");
	for(i=0, j=0;i<=28;i+=4, j++)
	{
		data = ptrace(PTRACE_PEEKDATA, pid, regs.esp+j*4, 0);
		printf("%04d| %p --> 0x%X\n",i,(void*)(regs.esp+j*4),data); 
	}
	printf("[------------------------------------------------]\n");
}
*/
int enable_breakpoint(pid_t pid, breakpoint* bp)
{
	assert(bp->addr); //NULL POINTER CHECK
	ptrace(PTRACE_POKETEXT, pid, bp->addr, (bp->orig_code & TRAP_MASK) | TRAP_INST); 
}

int run_instruction(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins) 
	//breakpoint까지 위치하게 한다. 
{	
	struct user_regs_struct regs; 
	int wait_status;
	*run_bit = 1;
	ptrace(PTRACE_CONT, pid, 0, 0); //breakpoint까지 cont됨.  //여기서 eip를 -1해서 하는 작업을 여기서 한다. 
	wait(&wait_status);
    if(WIFEXITED(wait_status))
	{
		return 0; 
	}	
	else if(WIFSTOPPED(wait_status))
	{
		ptrace(PTRACE_GETREGS, pid, 0, &regs);
		regs.eip = regs.eip - 1; //backstep 
		ptrace(PTRACE_SETREGS, pid, 0, &regs);  //in3을 실행하기 전으로 넘김. 그리고 반납. step_into or continue
		show_information(pid, head_ins);
		return 0; 
	    	
	}
	//show_infomation(pid, head_bp);
}

/*현재 bp에서 다음 bp까지 움직임. cont보단 single step으로 ㅈㄴ게 돌리면
  현재 위치점이랑 bp리스트에서 비교한 뒤 그걸 기준으로 다음 bp까지 single step돌리면 됨.
  현재 존재하느 bp가 없으면 쭉 실행한 다음 WIFEXITED로 검사하면 됨. */

/*
처음 시작할 때 bp의 지점이면 disable 해주고 single -> enable한뒤 밑에 루틴 수행 
고려해야 할것 :: 현재 위치가 bp의 자리일땐 disable해주소 enable해주어야 함. 
그리고 singlestep으로 돌린다음 ptrace_peektext로 값을 꺼내서 0xcc랑 비교하면 됨. 
*/
/*bp가 아닌 곳에서 cont하면 에러뜸 bp인곳에서 해야 에러가 안뜨네 */
int cont_instruction(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins)
{
	struct user_regs_struct regs; 
	int wait_status; 
	int retval;
	long data;
	int until=0;//다음 bp의 존재
	breakpoint* bp = head_bp->next; 
	if(*run_bit != 1)
	{
		printf("\ncotinue command is not execute\n");  
		printf("msg : the program is not being run.\n"); 
		return -1; 
	}

	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	while(bp != NULL)
	{
		if(regs.eip == (long)(bp->addr))
		{
			data = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0); 
			//assert((data & 0xFF) == TRAP_INST);
			ptrace(PTRACE_POKETEXT, pid, bp->addr, (data & TRAP_MASK) | (bp->orig_code & 0xFF));
			ptrace(PTRACE_SINGLESTEP, pid, 0, 0); 
			wait(&wait_status); 
			ptrace(PTRACE_GETREGS, pid, 0, &regs);
			/*again breakpoint create not add*/
			enable_breakpoint(pid, bp);  
			break;
		}
		bp = bp->next;
	}
	bp = (breakpoint*)head_bp->next;
	/*다음 bp를 만날 때 문제가 발생하는 듯*/
	while(1) 
	{
		//printf("test\n");
		ptrace(PTRACE_GETREGS, pid, 0, &regs); 
		while(bp != NULL)
		{
			//printf("test1 : %lX\ntest2 : %lX\n",regs.eip, (long)bp->addr); //bp list가 문제인거 같은데 
			if(regs.eip == (long)(bp->addr))
			{
				show_information(pid, head_ins);
				return 0; 
			}
			else{
			bp = bp->next;  //bp list를 처음으로 돌려야하네 
			}
		}
		bp = head_bp->next; //bp list를 처음으로 돌린다. 
		ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
		wait(&wait_status); 
		if(WIFEXITED(wait_status))
		{
			*run_bit = 0;
			printf("\nmsg : the program is exied.\n"); 
			return 0;
		}
	}	
	//printf("ok 2\n");
	show_information(pid, head_ins); 
	return 0;
}

int step_over(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins)
{
	struct user_regs_struct regs; 
	int retval; 
	int wait_status; 
	if(*run_bit != 1)
	{
		perror("the program is not being run."); 
		return -1;
	} 
	//다음 함수의 주소값을 받아서 거기까지 PTRACE_CONT하자. 
	//disassembler.c에서 선언된 instruction 구조체 끌고와서 사용하자. 
}
/*만약 다음 step into하다가 bp에 도착한다면?*/
int step_into(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins)
{
	breakpoint* bp = (breakpoint*)head_bp->next; 
	struct user_regs_struct regs; 
	int wait_status;
	if(*run_bit != 1)
	{
		printf("\nstep into command is not execute\n");
		printf("msg : the program is not being run.\n");
		return -1;
	}
	ptrace(PTRACE_GETREGS, pid, 0, &regs); 
	while(bp != NULL)
	{
		if(regs.eip == (long)(bp->addr)) //+1해서 비교하는 부분을 빼고 그냥 현 위치를 비교하게 하자. 
		{
			/*temp disable breakpoint not delete*/
			unsigned data = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0); 
			printf("test : %x\n",data);
			//assert((data & 0xFF) == TRAP_INST); 
			//ptrace(PTRACE_POKETEXT, pid, bp->addr, (bp->orig_code & TRAP_MASK) | TRAP_INST);
			ptrace(PTRACE_POKETEXT, pid, bp->addr, (data & TRAP_MASK) | (bp->orig_code & 0xFF)); 
			
			ptrace(PTRACE_SINGLESTEP, pid, 0, 0); 
			wait(&wait_status); 
			
			/*again breakpoint create not add*/
			enable_breakpoint(pid, bp);  
			show_information(pid, head_ins); 
			return 0; 
		}
		bp = bp->next; 
	}

	ptrace(PTRACE_SINGLESTEP, pid, 0, 0); 
	wait(&wait_status); 
	show_information(pid, head_ins); 
	if(WIFEXITED(wait_status))
	{
		printf("\nstep into command is not execute\n");
		printf("msg : the program is exited.\n");
		*run_bit = 0;
		return -1; 
	}
	return 0; 
	
}

void payload_inject(pid_t pid, unsigned addr, char* buffer, unsigned size){
	unsigned *src = (unsigned*)buffer; 
	//printf("size %d\n", size);
	for(int i=0;i<size;i+=4, addr+=4,src++){
		//printf("shell : %d\n", *src);
		ptrace(PTRACE_POKEDATA, pid, addr, *src); 
	}
}

void inject_process_memory(pid_t pid, unsigned from_addr, unsigned data, unsigned data_size)
{
	unsigned swap_bit; 
	switch(data_size){
		case 1:
			ptrace(PTRACE_POKEDATA, pid, from_addr, (char)data);
			break; 
		case 2:
			break; 
		case 4:
			//swap_bit = fourSwap(data); 
			ptrace(PTRACE_POKEDATA, pid, from_addr, data); 
			break; 
		default:
			break; 
	}
	//ptrace(PTRACE_POKEDATA, pid, from_addr, data);
	 
}

void dump_process_memory(pid_t pid, unsigned from_addr, unsigned size)
{
	if(size <= 0 || size >= 10000)
	{
		printf("size is too small and too big!\n");
		exit(1); 
	}
	unsigned char buff[size]; 
	int i=0;
	unsigned addr;
	printf("\nDump memory from [0x%08X ~ 0x%08X]\n", from_addr, from_addr+size); 
	printf("------------------------------------\n");
	for (addr = from_addr; addr <= from_addr+size; ++addr)
	{
		unsigned char word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0); 
		buff[i] = word; 
		//printf("[%d]: 0x%08X: %02x\n",i, addr, word & 0xFF); 
		i++;
	}
	dumpcode(buff, size, from_addr);
	printf("------------------------------------\n");
}

int create_breakpoint(pid_t pid, breakpoint* head_bp, target_addr_t addr)  //기준 노드(head_bp)를 중심. 
{
	//error check addr is in memory 
	breakpoint* bp = (breakpoint*)malloc(sizeof(breakpoint));
    breakpoint* temp = head_bp; 
	while(temp->next != NULL)
	{
		temp = (breakpoint*)temp->next; 
	}
	temp->next = (breakpoint*)bp;  //리스트의 끝에 붙임. 
	bp->next = NULL; 
	bp->addr = addr; 
	bp->orig_code = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0); 
	enable_breakpoint(pid, bp); //해당 bp를 넘김 여긴 head_bp를 넘겨서 순회할 필요가 없음.  
}





