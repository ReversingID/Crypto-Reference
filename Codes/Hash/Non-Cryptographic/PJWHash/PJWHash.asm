	.file	"PJWHash.c"
	.intel_syntax noprefix
	.text
	.globl	_PJWHash
	.def	_PJWHash;	.scl	2;	.type	32;	.endef
_PJWHash:
	push	ebp
	mov	ebp, esp
	sub	esp, 32
	mov	DWORD PTR [ebp-12], 32
	mov	edx, DWORD PTR [ebp-12]
	mov	eax, edx
	add	eax, eax
	add	eax, edx
	shr	eax, 2
	mov	DWORD PTR [ebp-16], eax
	mov	eax, DWORD PTR [ebp-12]
	shr	eax, 3
	mov	DWORD PTR [ebp-20], eax
	mov	eax, DWORD PTR [ebp-12]
	sub	eax, DWORD PTR [ebp-20]
	mov	edx, -1
	mov	ecx, eax
	sal	edx, cl
	mov	eax, edx
	mov	DWORD PTR [ebp-24], eax
	mov	DWORD PTR [ebp-28], 0
	mov	DWORD PTR [ebp-4], 0
	mov	DWORD PTR [ebp-8], 0
	mov	DWORD PTR [ebp-8], 0
	jmp	L2
L4:
	mov	eax, DWORD PTR [ebp-20]
	mov	edx, DWORD PTR [ebp-4]
	mov	ecx, eax
	sal	edx, cl
	mov	eax, DWORD PTR [ebp+8]
	movzx	eax, BYTE PTR [eax]
	movsx	eax, al
	add	eax, edx
	mov	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	and	eax, DWORD PTR [ebp-24]
	mov	DWORD PTR [ebp-28], eax
	cmp	DWORD PTR [ebp-28], 0
	je	L3
	mov	eax, DWORD PTR [ebp-16]
	mov	edx, DWORD PTR [ebp-28]
	mov	ecx, eax
	shr	edx, cl
	mov	eax, edx
	xor	eax, DWORD PTR [ebp-4]
	mov	edx, DWORD PTR [ebp-24]
	not	edx
	and	eax, edx
	mov	DWORD PTR [ebp-4], eax
L3:
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
