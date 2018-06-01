	.file	"ELFHash.c"
	.intel_syntax noprefix
	.text
	.globl	_ELFHash
	.def	_ELFHash;	.scl	2;	.type	32;	.endef
_ELFHash:
	push	ebp
	mov	ebp, esp
	sub	esp, 16
	mov	DWORD PTR [ebp-12], 0
	mov	DWORD PTR [ebp-4], 0
	mov	DWORD PTR [ebp-8], 0
	mov	DWORD PTR [ebp-8], 0
	jmp	L2
L4:
	mov	eax, DWORD PTR [ebp-4]
	sal	eax, 4
	mov	edx, eax
	mov	eax, DWORD PTR [ebp+8]
	movzx	eax, BYTE PTR [eax]
	movsx	eax, al
	add	eax, edx
	mov	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	and	eax, -268435456
	mov	DWORD PTR [ebp-12], eax
	cmp	DWORD PTR [ebp-12], 0
	je	L3
	mov	eax, DWORD PTR [ebp-12]
	shr	eax, 24
	xor	DWORD PTR [ebp-4], eax
L3:
	mov	eax, DWORD PTR [ebp-12]
	not	eax
	and	DWORD PTR [ebp-4], eax
	add	DWORD PTR [ebp+8], 1
	add	DWORD PTR [ebp-8], 1
L2:
	mov	eax, DWORD PTR [ebp-8]
	cmp	eax, DWORD PTR [ebp+12]
	jb	L4
	mov	eax, DWORD PTR [ebp-4]
	leave
	ret
	.ident	"GCC: (tdm64-1) 5.1.0"
