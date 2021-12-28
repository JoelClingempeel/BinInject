        .global _start
        .text
_start:
	mov     $1, %rax
        mov     $1, %rdi
	lea	(%rip), %rsi
	add	$24, %rsi
        mov     $36, %rdx
        syscall
	mov     $60, %rax
        xor     %rdi, %rdi
        syscall

msg:
        .ascii  "Muahahaha - file has been hijacked\n"
