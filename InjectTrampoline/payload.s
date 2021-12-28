        .global _start
        .text
_start:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	mov     $1, %rax
        mov     $1, %rdi
	lea	(%rip), %rsi
	add	$14, %rsi
        mov     $35, %rdx
        syscall
	ret
msg:
        .ascii  "Muahahaha - file has been hijacked\n"
