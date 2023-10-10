# Instruction
32bit ELF 바이너리 정적 및 동적 디버거입니다. 

# Compile 
대학교 1학년 때 만들 것이라 Makefile을 몰랐던 때입니다.   
32bit로 컴파일할 수 있는 gcc-multilib가 필요합니다. 
또한 분석대상 바이너리는 32비트입니다. 
```Shell
gcc -m32 ListBaseStack.c disassembler.c ptrace.c -g
```

# Usage
오류 예외처리를 몰랐던 시기라 오류가 많이 납니다. 
```Shell
➜  Debugger git:(master) ✗ ./a.out hello
text : 880
text : 564
su debugger v1.0.0
if you want to help, input : $sd help
$sd
```

```Shell
$sd help

$sd print symbol :: print <hello>'s <symbol_name>
$sd disasm <symbol_name> :: disassemble <symbol_name>
$sd addr disasm <direct address> :: disassemble address
$sd quit or q :: quit debugger
$sd b <direct address> :: create breakpoint in address
$sd r :: running program
$sd c :: continue until breakpoint
$sd n :: step over
$sd s :: step into
$sd info b :: print breakpoint
$sd info r :; print register
$sd del <breakpoint index> :: delete breakpoint <index>
$sd dump <address> <size> :: dump memory from addr as size
$sd inject <address> <value> <size> :: inject value in memory as size
$sd payload <address> <payload file>
$sd set <regsiter> <value> :: set register with value
$sd show :: show info register, code, stack, stackframe
$sd declare <name> <address> :: show <name> in stackframe
$sd history :: show input command
$sd list_def :: show def list
will adding...ahhhhhh!
```

```Shell
$sd print symbol
===============================================
[hello] symbol name
[44] : __init_array_end
[45] : _DYNAMIC
[46] : __init_array_start
[47] : __GNU_EH_FRAME_HDR
[48] : _GLOBAL_OFFSET_TABLE_
[49] : __libc_csu_fini
[50] : __x86.get_pc_thunk.bx
[51] : data_start
[52] : printf@@GLIBC_2.0
[53] : _edata
[54] : _fini
[55] : __stack_chk_fail@@GLIBC_2.4
[56] : __data_start
[57] : __gmon_start__
[58] : __dso_handle
[59] : _IO_stdin_used
[60] : __libc_start_main@@GLIBC_2.0
[61] : func
[62] : __libc_csu_init
[63] : _end
[64] : _dl_relocate_static_pie
[65] : _start
[66] : _fp_hw
[67] : __bss_start
[68] : main
[69] : __x86.get_pc_thunk.ax
[70] : __stack_chk_fail_local
[71] : __TMC_END__
[72] : _init
```

```Shell
$sd disasm main

0x080484d1: <main>

0x080484d1 <+   0>:     lea ecx, dword ptr [esp+*1+0x4]
0x080484d5 <+   4>:     and esp, -0x10
0x080484d8 <+   7>:     push dword ptr [ecx-0x4]
0x080484db <+  10>:     push ebp
0x080484dc <+  11>:     mov ebp, esp
0x080484de <+  13>:     push ebx
0x080484df <+  14>:     push ecx
0x080484e0 <+  15>:     call 80483c0
0x080484e5 <+  20>:     add ebx, 0x1b1b
0x080484eb <+  26>:     call 8048482
0x080484f0 <+  31>:     sub esp, 0xc
0x080484f3 <+  34>:     lea eax, dword ptr [ebx-0x1a40]
0x080484f9 <+  40>:     push eax
0x080484fa <+  41>:     call 8048330
0x080484ff <+  46>:     add esp, 0x10
0x08048502 <+  49>:     mov eax, 0x0
0x08048507 <+  54>:     lea esp, dword ptr [ebp-0x8]
0x0804850a <+  57>:     pop ecx
0x0804850b <+  58>:     pop ebx
0x0804850c <+  59>:     pop ebp
0x0804850d <+  60>:     lea esp, dword ptr [ecx-0x4]
0x08048510 <+  63>:     ret
$sd
```

```Shell
$sd b 0x080484d1
$sd info b

[information : breakpoint]
[0] 0x80484d1
```

```Shell
[--------------------register--------------------]
EAX: 0x80484D1
EBX: 0xF7F70000
ECX: 0xFF82DCF0
EDX: 0xFF82DD10
ESI: 0xFF82DDA4
EDI: 0xF7FC3B80
EBP: 0xFF82DCD8
ESP: 0xFF82DCD0
EIP: 0x80484E0
[----------------------code----------------------]
 => 80484e0 <+  15> call 80483c0
    80484e5 <+  20> add ebx, 0x1b1b
    80484eb <+  26> call 8048482
    80484f0 <+  31> sub esp, 0xc
    80484f3 <+  34> lea eax, dword ptr [ebx-0x1a40]
    80484f9 <+  40> push eax
    80484fa <+  41> call 8048330
    80484ff <+  46> add esp, 0x10
    8048502 <+  49> mov eax, 0x0
[----------------------stack---------------------]
0000| 0xff82dcd0 --> 0xFF82DCF0
0004| 0xff82dcd4 --> 0xF7F70000
0008| 0xff82dcd8 --> 0xF7FC4020
0012| 0xff82dcdc --> 0xF7D67519
0016| 0xff82dce0 --> 0xFF82E217
0020| 0xff82dce4 --> 0x70
0024| 0xff82dce8 --> 0xF7FC4000
0028| 0xff82dcec --> 0xF7D67519
[-------------------Stack Frame------------------]
┏──────────────────────────────────┓
┠──────────────────────────────────┨
│00000008│0xff82dcd0 --> 0xFF82DCF0│<---ESP
┠──────────────────────────────────┨
│00000004│0xff82dcd4 --> 0xF7F70000│
┠──────────────────────────────────┨
│00000000│0xff82dcd8 --> 0xF7FC4020│<---EBP
┠──────────────────────────────────┨
│-0000004│0xff82dcdc --> 0xF7D67519│
┠──────────────────────────────────┨
│-0000008│0xff82dce0 --> 0xFF82E217│
┠──────────────────────────────────┨
│-0000012│0xff82dce4 --> 0x00000070│
┠──────────────────────────────────┨
│-0000016│0xff82dce8 --> 0xF7FC4000│
┠──────────────────────────────────┨
│-0000020│0xff82dcec --> 0xF7D67519│
┠──────────────────────────────────┨
│-0000024│0xff82dcf0 --> 0x00000001│
┠──────────────────────────────────┨
│-0000028│0xff82dcf4 --> 0xFF82DDA4│
┖──────────────────────────────────┚
$sd s
```

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
