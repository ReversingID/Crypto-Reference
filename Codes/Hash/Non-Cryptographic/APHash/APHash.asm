	.file	"APHash.c"
	.intel_syntax noprefix
	.text
	.globl	_APHash
	.def	_APHash;	.scl	2;	.type	32;	.endef
_APHash:
	push	ebp
	mov	ebp, esp
	sub	esp, 16
	mov	DWORD PTR [ebp-4], -1431655766
	mov	DWORD PTR [ebp-8], 0
	mov	DWORD PTR [ebp-8], 0
	jmp	L2
L5:
	mov	eax, DWORD PTR [ebp-8]
	and	eax, 1
	test	eax, eax
	jne	L3
	mov	eax, DWORD PTR [ebp-4]
	sal	eax, 7
	mov	ecx, eax
	mov	eax, DWORD PTR [ebp+8]
	movzx	eax, BYTE PTR [eax]
	movzx	eax, al
	mov	edx, DWORD PTR [ebp-4]
	shr	edx, 3
	imul	eax, edx
	xor	eax, ecx
	jmp	L4
L3:
	mov	eax, DWORD PTR [ebp-4]
	sal	eax, 11
	mov	ecx, eax
	mov	eax, DWORD PTR [ebp+8]
	movzx	eax, BYTE PTR [eax]
	movzx	eax, al
	mov	edx, DWORD PTR [ebp-4]
	shr	edx, 5
	xor	eax, edx
	add	eax, ecx
	not	eax
L4:
	xor	DWORD PTR [ebp-4], eax
	add	DWORD PTR [ebp+8], 1
	add	DWORD PTR [ebp-8], 1
L2:
	mov	eax, DWORD PTR [ebp-8]
	cmp	eax, DWORD PTR [ebp+12]
	jb	L5
	mov	eax, DWORD PTR [ebp-4]
	leave
	ret
	.ident	"GCC: (tdm64-1) 5.1.0"
