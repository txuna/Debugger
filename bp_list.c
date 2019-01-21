#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <unistd.h>

/*define value*/
#define TRAP_MASK 0xFFFFFF00
#define TRAP_INST 0xCC
typedef long target_addr_t; 

typedef struct BreakPoint{
	target_addr_t addr; 
	long orig_code;
    struct BreakPoint* next; //다음 bp 구조체의 주소를 담음. 	
}breakpoint;

//int break_index = 0; 


/*function*/
//int child_ptrace(); 
//int run_debugger(pid_t pid); 
breakpoint* create_breakpoint(breakpoint* bp, target_addr_t addr); 
//target_addr_t get_eip(pid_t pid); 
int enable_breakpoint(breakpoint* bp); 
//breakpoint* set_breakpoint(pid_t pid, target_addr_t addr);
int delete_breakpoint(breakpoint* head_bp, int index);
int disable_breakpoint(breakpoint* head_bp, int index); 
void print_breakpoint(breakpoint* head_bp); 

int main(int argc, char** argv)
{
	breakpoint* head_bp = (breakpoint*)malloc(sizeof(breakpoint));  	
	head_bp->next = NULL;  //head_bp가 기준 노드임 //여기엔 값을 넣지 않음. 
	int menu, index;
	target_addr_t addr;
	while(1)
	{
		printf("select menu 1.add bp, 2.del bp, 3.show bp: ");
		scanf("%d", &menu);
		switch(menu)
		{
			case 1:
				printf("input address : ");
				scanf("%ld", &addr); 
				create_breakpoint(head_bp, addr); 
				break; 
			case 2: 
				printf("input index : ");
				scanf("%d", &index); 
				disable_breakpoint(head_bp, index);
				break;

			case 3:
				print_breakpoint(head_bp); 

		}
	}
	return 0; 
}

int disable_breakpoint(breakpoint* head_bp, int index)
{
	//여기서 opcode 되돌리고 delete_breakpoint함수 호출 
	delete_breakpoint(head_bp, index); 
}
//command info breakpoint => index로 보여줌 

void print_breakpoint(breakpoint* head_bp)
{
	int i=0;
	breakpoint* curr = (breakpoint*)head_bp->next; 
	printf("[information : breakpoint]\n");
	while( curr !=	NULL)
	{
		printf("[%d] 0x%08lx\n",i, curr->addr); 
		i++;
	    curr = curr->next;	
	}
}

int delete_breakpoint(breakpoint* head_bp, int index)
{ //index만큼 while을 돌림. 돌리고 해당 index에 주소가 있는지 없는지 확인함. 
	breakpoint* curr = (breakpoint*)head_bp->next; 
	breakpoint* before = head_bp;
	int i; 
	if(curr == NULL)
	{
		perror("breakpoint (null pointer errro)"); 
		return -1; 
	}
	//before = curr; 

	for(i=0;i,i<index;i++) 
	{	
		before = curr; 
		curr = (breakpoint*)curr->next; 
		if(curr == NULL)
		{
			perror("not breakpoint index (null pointer error)"); 
			return -1;
		}
	}
	before->next = curr->next; 
	//printf("test : %p\n",before->next);
    free(curr);
	return 0; 	
}

int enable_breakpoint(breakpoint* bp)
{
	//assert(bp->addr); //NULL POINTER CHECK
	//ptrace(PTRACE_POKETEXT, pid, bp->addr, (orig & TRAP_MASK) | TRAP_INST); 
}

breakpoint* create_breakpoint(breakpoint* head_bp, target_addr_t addr)  //기준 노드(head_bp)를 중심. 
{
	breakpoint* bp = (breakpoint*)malloc(sizeof(breakpoint));
    breakpoint* temp = head_bp; 
	while(temp->next != NULL)
	{
		temp = (breakpoint*)temp->next;
		printf("1234\n");
	}
	temp->next = (breakpoint*)bp; 
	bp->next = NULL; 
	bp->addr = addr;

		

	//head_bp->next = (breakpoint*)bp; 
	
//	bp->next = head_bp->next; //다음 리스트의 주소값을 담음. 
//	bp->addr = addr;  	//breakpoint address 
	//bp->orig = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0);  //backup 

//	head_bp->next = (breakpoint*)bp; 

	//enable_breakpoint(pid, bp); 
}
/*
target_addr_t get_eip(pid_t pid)
{
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
   	return (target_addr_t)regs.eip; 	
}

int run_debugger(pid_t pid)
{

}

int child_ptrace(const char* program_name)
{
	if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
	{
		perror("ptrace");
		return -1;  
	}
	execl(program_name, program_name, 0); 
}
*/





