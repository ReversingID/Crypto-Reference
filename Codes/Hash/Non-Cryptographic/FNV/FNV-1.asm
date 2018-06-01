	.file	"FNV-1.c"
	.intel_syntax noprefix
	.text
	.globl	_FNVHash
	.def	_FNVHash;	.scl	2;	.type	32;	.endef
_FNVHash:
	push	ebp
	mov	ebp, esp
	sub	esp, 16
	mov	DWORD PTR [ebp-4], 0
	mov	DWORD PTR [ebp-8], -2128831035
	mov	DWORD PTR [ebp-4], 0
	jmp	L2
L3:
	mov	eax, DWORD PTR [ebp-8]
	imul	eax, eax, 16777619
	mov	DWORD PTR [ebp-8], eax
	mov	edx, DWORD PTR [ebp+8]
	mov	eax, DWORD PTR [ebp-4]
	add	eax, edx
	movzx	eax, BYTE PTR [eax]
	movsx	eax, al
	xor	DWORD PTR [ebp-8], eax
	add	DWORD PTR [ebp-4], 1
L2:
	mov	eax, DWORD PTR [ebp-4]
	cmp	eax, DWORD PTR [ebp+12]
	jb	L3
	mov	eax, DWORD PTR [ebp-8]
	leave
	ret
	.ident	"GCC: (tdm64-1) 5.1.0"
