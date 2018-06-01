	.file	"Murmur3.c"
	.intel_syntax noprefix
	.text
	.globl	_Murmur3
	.def	_Murmur3;	.scl	2;	.type	32;	.endef
_Murmur3:
	push	ebp
	mov	ebp, esp
	sub	esp, 32
	mov	eax, DWORD PTR [ebp+16]
	mov	DWORD PTR [ebp-4], eax
	cmp	DWORD PTR [ebp+12], 3
	jbe	L2
	mov	eax, DWORD PTR [ebp+8]
	mov	DWORD PTR [ebp-8], eax
	mov	eax, DWORD PTR [ebp+12]
	shr	eax, 2
	mov	DWORD PTR [ebp-12], eax
L3:
	mov	eax, DWORD PTR [ebp-8]
	lea	edx, [eax+4]
	mov	DWORD PTR [ebp-8], edx
	mov	eax, DWORD PTR [eax]
	mov	DWORD PTR [ebp-24], eax
	mov	eax, DWORD PTR [ebp-24]
	imul	eax, eax, -862048943
	mov	DWORD PTR [ebp-24], eax
	rol	DWORD PTR [ebp-24], 15
	mov	eax, DWORD PTR [ebp-24]
	imul	eax, eax, 461845907
	mov	DWORD PTR [ebp-24], eax
	mov	eax, DWORD PTR [ebp-24]
	xor	DWORD PTR [ebp-4], eax
	rol	DWORD PTR [ebp-4], 13
	mov	edx, DWORD PTR [ebp-4]
	mov	eax, edx
	sal	eax, 2
	add	eax, edx
	sub	eax, 430675100
	mov	DWORD PTR [ebp-4], eax
	sub	DWORD PTR [ebp-12], 1
	cmp	DWORD PTR [ebp-12], 0
	jne	L3
L2:
	mov	eax, DWORD PTR [ebp+12]
	and	eax, 3
	test	eax, eax
	je	L4
	mov	eax, DWORD PTR [ebp+12]
	and	eax, 3
	mov	DWORD PTR [ebp-16], eax
	mov	DWORD PTR [ebp-20], 0
	mov	eax, DWORD PTR [ebp-16]
	sub	eax, 1
	add	DWORD PTR [ebp+8], eax
L5:
	sal	DWORD PTR [ebp-20], 8
	mov	eax, DWORD PTR [ebp+8]
	lea	edx, [eax-1]
	mov	DWORD PTR [ebp+8], edx
	movzx	eax, BYTE PTR [eax]
	movzx	eax, al
	or	DWORD PTR [ebp-20], eax
	sub	DWORD PTR [ebp-16], 1
	cmp	DWORD PTR [ebp-16], 0
	jne	L5
	mov	eax, DWORD PTR [ebp-20]
	imul	eax, eax, -862048943
	mov	DWORD PTR [ebp-20], eax
	rol	DWORD PTR [ebp-20], 15
	mov	eax, DWORD PTR [ebp-20]
	imul	eax, eax, 461845907
	mov	DWORD PTR [ebp-20], eax
	mov	eax, DWORD PTR [ebp-20]
	xor	DWORD PTR [ebp-4], eax
L4:
	mov	eax, DWORD PTR [ebp+12]
	xor	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	shr	eax, 16
	xor	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	imul	eax, eax, -2048144789
	mov	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	shr	eax, 13
	xor	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	imul	eax, eax, -1028477387
	mov	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	shr	eax, 16
	xor	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	leave
	ret
	.ident	"GCC: (tdm64-1) 5.1.0"
