	.file	"RSHash.c"
	.intel_syntax noprefix
	.text
	.globl	_RSHash
	.def	_RSHash;	.scl	2;	.type	32;	.endef
_RSHash:
	push	ebp
	mov	ebp, esp
	sub	esp, 16
	mov	DWORD PTR [ebp-16], 378551
	mov	DWORD PTR [ebp-4], 63689
	mov	DWORD PTR [ebp-8], 0
	mov	DWORD PTR [ebp-12], 0
	mov	DWORD PTR [ebp-12], 0
	jmp	L2
L3:
	mov	eax, DWORD PTR [ebp-8]
	imul	eax, DWORD PTR [ebp-4]
	mov	edx, eax
	mov	eax, DWORD PTR [ebp+8]
	movzx	eax, BYTE PTR [eax]
	movsx	eax, al
	add	eax, edx
	mov	DWORD PTR [ebp-8], eax
	mov	eax, DWORD PTR [ebp-4]
	imul	eax, DWORD PTR [ebp-16]
	mov	DWORD PTR [ebp-4], eax
	add	DWORD PTR [ebp+8], 1
	add	DWORD PTR [ebp-12], 1
L2:
	mov	eax, DWORD PTR [ebp-12]
	cmp	eax, DWORD PTR [ebp+12]
	jb	L3
	mov	eax, DWORD PTR [ebp-8]
	leave
	ret
	.ident	"GCC: (tdm64-1) 5.1.0"
