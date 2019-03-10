;삽입정렬 어셈블리 서브루틴 
;atoi로의 반환값을 하면 그 값을 정수형 배열에 넣고 접근하자. 
;insert_sort(int size, int* number); 

SYS_CALL equ 0x80 

segment .data 
	;array dd 2,3,4,1,5  test 
	;size dd 5			 test	
segment .bss 

segment .text 
	global insert_sort
	;global _start

insert_sort:	;[ebp+8] size, [ebp+12] number_array 
	push ebp 
	mov ebp, esp 
	mov esi, [ebp+12]	;int* number  

	mov edx, 1			; i = 1
	xor ecx, ecx 		; temp =0
	xor ebx, ebx 		; j =0  
	
	;mov edx, [ebp-4]	; edx = i 
	
one_sort_loop:
	cmp edx, [ebp+8] 	;size 
	;cmp edx, [ebp+8] 
	je one_sort_loop_end
	mov ecx, [esi+edx*4] 

	mov ebx, edx 
	dec ebx 	;j = i - 1

two_sort_loop:
	cmp ebx, 0 
	jl two_sort_loop_end
	cmp ecx, [esi+ebx*4] ;if(arr[j] > temp) 
	jge two_sort_loop_end	;else 
	xor eax, eax 
	mov eax, [esi+ebx*4] 
	mov [esi+ebx*4+4], eax	;arr[j+1] = arr[j]  
	dec ebx 	
	jmp two_sort_loop 
		 	
two_sort_loop_end: 
	mov [esi+ebx*4+4], ecx ;[esi+ebx*1+1] 
	inc edx
	jmp one_sort_loop 

one_sort_loop_end:		
	pop ebp   	
	ret 


