;atoi 구하는 모듈 gets까지 가능 프로토타입 : atoi_gets(char* string) 
;지금은 여기서 스택 할당하는데 모듈화시 ebp+8에서 챙김. 

GETS_BUF equ 10 
BASE equ 10 
SYS_CALL equ 0x80
;ENTER equ 0x10 
NULL equ 0x00 
ASCII_ZERO equ 0x30 
;BYTE equ 1 

segment .data 

segment .bss 

segment .text 
	global atoi_gets
	;global _start ;모듈화시 asm_gets로 바꿀것  atoi_gets(char* string) 
	global asm_gets 		;asm_gets(char* string) 
	global asm_strlen 		;
	global asm_puts 		;
	global asm_atoi 		;asm_gets(char* string, int count)
	;global remove_enter		;

atoi_gets: 
	push ebp 
	mov ebp, esp 
	
	sub esp, GETS_BUF
	lea eax, [ebp-GETS_BUF] 	; mov eax, [ebp+8] 
	;mov eax, [ebp+8] 	
	push eax 					; push eax 
	call asm_gets 
	add esp, 4
	
	;push eax 
	;call asm_puts
	;add esp, 4

	add esp, GETS_BUF 
	pop ebp 
	ret
	;mov eax, 1 
	;int SYS_CALL ;module -> ret 

asm_gets: 
	push ebp 
	mov ebp, esp 

	mov eax, 0x3
	mov ebx, 0 
	mov ecx, [ebp+0x8]
	mov edx, GETS_BUF 
	int SYS_CALL  ; return to eax, success read byte 
	
	dec eax ;decrease ENTER '\n'

	push dword [ebp+0x8]
	push eax	
	call asm_atoi
	;call remove_enter  그냥 eax값을 하나 줄이면 편할듯. 
	add esp, 8
		
	pop ebp 
	ret 

asm_atoi:  		;ebp+12 : string, ebp+8 count 
	push ebp 
	mov ebp, esp 
	;sub esp, 4 	 ;loop_count 
	mov ecx, [ebp+8] ;loop_count 
	;dec ecx 		 ; start index 0 
	mov esi, [ebp+12] ;string 
	xor eax, eax  	 ;return number, num = 0
	xor edx, edx     ;temp variable
	mov ebx, BASE

asm_atoi_loop:  ;umm.. test little endian 
	cmp ecx, 0x0 
	je asm_atoi_loop_end 
	mul ebx							;num = num * base_10 -> eax = eax * 10
	mov dl, byte [esi]
	sub edx, ASCII_ZERO
	add eax, edx						;num = num + (str[i] - ASCII_ZERO) 
	inc esi 
	dec ecx 
	jmp asm_atoi_loop

asm_atoi_loop_end: 
	pop ebp 
	ret




























