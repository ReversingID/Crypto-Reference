	.file	"DJBHash.c"
	.intel_syntax noprefix
	.text
	.globl	_DJBHash
	.def	_DJBHash;	.scl	2;	.type	32;	.endef
_DJBHash:
	push	ebp
	mov	ebp, esp
	sub	esp, 16
	mov	DWORD PTR [ebp-4], 5381
	mov	DWORD PTR [ebp-8], 0
	mov	DWORD PTR [ebp-8], 0
	jmp	L2
L3:
	mov	eax, DWORD PTR [ebp-4]
	sal	eax, 5
	mov	edx, eax
	mov	eax, DWORD PTR [ebp-4]
	add	edx, eax
	mov	eax, DWORD PTR [ebp+8]
	movzx	eax, BYTE PTR [eax]
	movsx	eax, al
	add	eax, edx
	mov	DWORD PTR [ebp-4], eax
	add	DWORD PTR [ebp+8], 1
	add	DWORD PTR [ebp-8], 1
L2:
	mov	eax, DWORD PTR [ebp-8]
	cmp	eax, DWORD PTR [ebp+12]
	jb	L3
	mov	eax, DWORD PTR [ebp-4]
	leave
	ret
	.ident	"GCC: (tdm64-1) 5.1.0"
