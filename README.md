# Instruction
32bit ELF 바이너리 정적 및 동적 디버거입니다. 

# Main Logic
```C
while(index < size) //file_vol
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
        /*

        ...

        */
    }
}
```
읽어들인 opcode들에 대해 intel x86 opcode 규칙에 따라 파싱을 진행합니다. 

```C
int step_into(pid_t pid, breakpoint* head_bp, int* run_bit, ins_list* head_ins)
{
	breakpoint* bp = (breakpoint*)head_bp->next; 
...
	ptrace(PTRACE_GETREGS, pid, 0, &regs); 
	while(bp != NULL)
	{
		if(regs.eip == (long)(bp->addr))
		{
			unsigned data = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0); 
			ptrace(PTRACE_POKETEXT, pid, bp->addr, (data & TRAP_MASK) | (bp->orig_code & 0xFF)); 
			
			ptrace(PTRACE_SINGLESTEP, pid, 0, 0); 
			wait(&wait_status); 
			enable_breakpoint(pid, bp);  
...
			return 0; 
		}
		bp = bp->next; 
	}
	ptrace(PTRACE_SINGLESTEP, pid, 0, 0); 
	wait(&wait_status); 
...
	return 0; 
}
```
ptrace api를 사용해서 opcode를 single step으로 실행합니다. 만일 해당 opcode가 0xcc 즉, breakpoint 인터럽트라면 기존 opcode로 대체하고 실행합니다. 실행 후 다시 0xcc로 대체합니다.

```C
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
			ptrace(PTRACE_POKEDATA, pid, from_addr, data); 
			break; 
		default:
			break; 
	}
}
```
PTRACE_POKEDATA flag를 사용하여 프로그램의 메모리에 원하는 주소에 데이터를 주입합니다.

```C
int create_breakpoint(pid_t pid, breakpoint* head_bp, target_addr_t addr) 
{
	//error check addr is in memory 
	breakpoint* bp = (breakpoint*)malloc(sizeof(breakpoint));
    breakpoint* temp = head_bp; 
	while(temp->next != NULL)
	{
		temp = (breakpoint*)temp->next; 
	}
	temp->next = (breakpoint*)bp; 
	bp->next = NULL; 
	bp->addr = addr; 
	bp->orig_code = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, 0); 
	enable_breakpoint(pid, bp); 
}
```
사용자가 원하는 주소에 breapoint를 설정합니다. 기존코드를 백업하고 0xCC코드로 대체합니다.


# Additional Description
Not yet, not support floating point and two byte opcode, three byte opcode.. etc... 

but, i will also add opcodes that have not been added. 

if you have a working error, or if you have any additional points, please leave a note or email me. 

# Patch Note
2019/1/13 :: I add some two byte opcode(jmp, movsx, movzx...) and memory size(dowrd ptr, word ptr, byte ptr) 

2019/1/14 :: I add command line to clean interface ! and i add <line number>

2019/1/21 :: I add breakpoint list 

2019/1/26 :: I finished my debugger, GG but, have many bug XD, i will fix!

2019/1/27 :: i fix some bug.. ex)strtab offset and position, size, symbol_number and I add direct address disasm! 
