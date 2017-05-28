#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <Openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <Openssl/sha.h>
#include <openssl/bn.h>
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#define N "FF807E694D915875B13F47ACDDA61CE11F62E034150F84660BF34026ABAF8C37"
#define E "010001"
#define D "45AEF3CB207EAD939BBDD87C8B0F0CFCC5A366A5AF2AC5FE1261D7547C625F51"
unsigned char plaintext[] =
"01. A quick brown fox jumps over the lazy dog.\n" \
"02. A quick brown fox jumps over the lazy dog.\n" \
"03. A quick brown fox jumps over the lazy dog.\n";
unsigned char IV[] = "0123456789ABCDEFDEADBEEFBADBEAD!";
unsigned char IV1[] = { 0xe3, 0x68, 0x2a, 0x22, 0x5b, 0x89, 0x90, 0xd9, 0x51,
					   0x31, 0x52, 0xa2, 0xc8, 0xcb, 0x02, 0xb4, 0xdb, 0x9b,
					   0xcb, 0x34, 0x85, 0xbc, 0x0c, 0xb6, 0x46, 0xc1, 0xf5,
					   0x28, 0x5d, 0x25, 0xa1, 0xff
};
void dump_hex(unsigned char *p, int n, unsigned char *q)
{
	int i;
	for (i = 0; i<n; i++)
	{
		sprintf((char *)&q[i * 2], "%02X", p[i]);
	}
	q[i * 2] = '\0';
}

void scan_hex(unsigned char *p, int n, unsigned char *q)
{
	int i;
	for (i = 0; i<n; i++)
	{
		sscanf((char *)&p[i * 2], "%02X", &q[i]);
	}
}
int main()
{
	int n = 0;
	unsigned char ciphertext[512];
	unsigned char ciphertext1[512];
	unsigned char bufin[256];
	unsigned char bufout[256];
	unsigned char m1[16], m2[20];
	unsigned char combine[36] = { 0 };
	unsigned char temp = 0;
	unsigned char final[256];
	unsigned char part1_ci[512];
	unsigned char part1_pl[512];
	int i = 0;
	int count = 0;
	int length = 0;
	RSA *prsa, *prsa1;
	BIGNUM *pn, *pe, *pd;

	prsa1 = RSA_new();
	prsa1->flags |= RSA_FLAG_NO_BLINDING;
	pn = BN_new();
	pe = BN_new();
	pd = BN_new();
	BN_hex2bn(&pn, N);
	BN_hex2bn(&pe, E);
	BN_hex2bn(&pd, D);

	prsa1->n = pn;
	prsa1->e = pe;
	prsa1->d = NULL;
	n = RSA_size(prsa1);

	//////////////////////////part1___step1___encrypt////////////////////////////
	printf("plaintext=\n");
	printf("%s", plaintext);
	printf("Encrypting...\nciphertext=\n");
	memset(bufout, 0, sizeof(bufout));
	memset(part1_ci, 0, sizeof(part1_ci));
	n = RSA_size(prsa1);
	length = strlen(plaintext);
	strcpy((char *)bufout, (char *)IV);
	strncpy((char *)bufin, (char *)plaintext + count, n);
	while (count + n < length)
	{
		for (i = 0; i < n; ++i)
			bufin[i] ^= bufout[i];
		RSA_public_encrypt(n, bufin, bufout, prsa1, RSA_NO_PADDING);
		for (i = 0; i < n; ++i)
			part1_ci[i + count] = bufout[i];
		count += n;
		strncpy((char *)bufin, (char *)plaintext + count, n);
	}
	count -= n;
	strncpy((char *)bufout, (char *)plaintext + count + n, length - count);
	strncpy((char *)bufin, (char *)part1_ci + count, n);
	strncpy((char *)part1_ci + count + n, (char *)part1_ci + count, length - count);
	for (i = 0; i < length - count; ++i)
		bufin[i] ^= bufout[i];
	RSA_public_encrypt(n, bufin, bufout, prsa1, RSA_NO_PADDING);
	for (i = 0; i < n; ++i)
		part1_ci[i + count] = bufout[i];
	for (i = 0; i < length; i++)
		printf("%02X", part1_ci[i]);
	printf("\n");

	//////////////////////////part1___step2___decrypt////////////////////////////
	prsa1->n = pn;
	prsa1->e = NULL;
	prsa1->d = pd;
	n = RSA_size(prsa1);


	memset(bufout, 0, sizeof(bufout));
	memset(bufin, 0, sizeof(bufout));
	memset(part1_pl, 0, sizeof(part1_pl));
	strncpy((char *)bufin, (char *)part1_ci + count, n);
	RSA_private_decrypt(n, bufin, bufout, prsa1, RSA_NO_PADDING);

	///////////////////////////////////////////////////////////////////
	memset(bufin, 0, sizeof(bufout));
	memcpy((char *)bufin, (char *)bufout, length - count - n);
	memcpy((char *)bufout, (char *)part1_ci + count + n, length - count);
	for (i = 0; i < length - count - n; ++i)
		bufin[i] ^= bufout[i];
	strncpy((char *)part1_pl + count + n, (char *)bufin, length - count);
	strncpy((char *)bufin, (char *)part1_ci + count + n, length - count);
	memset(&bufin[32], 0, sizeof(unsigned char) * 32);
	RSA_private_decrypt(n, bufin, bufout, prsa1, RSA_NO_PADDING);
	strncpy((char *)bufin, (char *)bufout, n);


	strncpy((char *)bufout, (char *)part1_ci + count - n, n);
	do
	{
		for (i = 0; i < n; ++i)
			bufin[i] ^= bufout[i];
		for (i = 0; i < n; ++i)
			part1_pl[i + count] = bufin[i];
		count -= n;
		memcpy((char *)bufin, (char *)part1_ci + count, n);
		RSA_private_decrypt(n, bufin, bufout, prsa1, RSA_NO_PADDING);
		memcpy((char *)bufin, (char *)bufout, n);
		if(count == 0)
			memcpy((char *)bufout, (char *)IV, n);
		else
			memcpy((char *)bufout, (char *)part1_ci + count - n, n);
	} while (count + n > 0);
	printf("Decrypting...\nplaintext=\n");
	printf("%s", part1_pl);
	RSA_free(prsa1);//free
					//////////////////////////part3___step1___hash////////////////////////////
	MD5(plaintext, strlen(plaintext), m1);
	SHA1(plaintext, strlen(plaintext), m2);
	printf("\nmd5=\n");
	for (i = 0; i < 16; i++)
		printf("%02X", m1[i]);
	printf("\n");
	printf("sha-1=\n");
	for (i = 0; i < 20; i++)
		printf("%02X", m2[i]);
	//////////////////////////part3___step2___combine/////////////////////////
	for (i = 0; i < 16; i++)
		combine[i] = m1[i];
	for (i = 0; i < 20; i++)
		combine[i + 16] = m2[i];
	printf("\nmd5+sha-1=\n");
	for (i = 0; i < 36; i++)
		printf("%02X", combine[i]);
	//////////////////////////part3___step3___encrypt/////////////////////////
	prsa = RSA_new();
	prsa->flags |= RSA_FLAG_NO_BLINDING;
	pn = BN_new();
	pe = BN_new();
	pd = BN_new();
	BN_hex2bn(&pn, N);
	BN_hex2bn(&pe, E);
	BN_hex2bn(&pd, D);

	prsa->n = pn;
	prsa->e = NULL;
	prsa->d = pd;
	n = RSA_size(prsa);
	///////////////////////ready
	memset(bufin, 0, sizeof(bufin));
	memset(bufout, 0, sizeof(bufout));
	for (i = 0; i < 32; ++i)
	{
		bufin[i] = combine[i];
	}

	puts("\nEncrypting...");
	n = RSA_private_encrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
	dump_hex(bufout, 4, &ciphertext[64]);//tail
										 //first part final¡ü
	memset(bufin, 0, sizeof(bufin));
	for (i = 0; i < 4; ++i)
	{
		bufin[i] = combine[i + 32];
	}
	for (i = 0; i < 28; ++i)
	{
		bufin[i + 4] = bufout[i + 4];
	}
	memset(bufout, 0, sizeof(bufout));
	n = RSA_private_encrypt(32, bufin, bufout, prsa, RSA_NO_PADDING);
	temp = ciphertext[64];
	dump_hex(bufout, n, ciphertext);
	ciphertext[64] = temp;

	printf("signature=\n%s\n", ciphertext);
	//////////////////////////part3___step3___decrypt/////////////////////////
	scan_hex(ciphertext, 36, ciphertext1);
	puts("Decrypting...\nplaintext=");
	prsa->e = pe;
	prsa->d = NULL;
	n = 32;

	//set bufin
	for (i = 0; i < 32; ++i)//copy head part
	{
		bufin[i] = ciphertext1[i];
	}
	memset(bufout, 0, sizeof(bufout));//set bufout
	n = RSA_public_decrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
	for (i = 0; i < 4; ++i)//copy the last block
	{
		final[i + 32] = bufout[i];
	}




	///////////follow part is to decrypt the n-1 block////////////////
	for (i = 0; i < 4; ++i)//copy head part
	{
		bufin[i] = ciphertext1[i + 32];
	}
	//stealing
	for (i = 0; i < 28; ++i)//copy tail part
	{
		bufin[i + 4] = bufout[i + 4];
	}
	/////////////bufin has been set/////////////////////////////





	memset(bufout, 0, sizeof(bufout));
	n = RSA_public_decrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
	for (i = 0; i < 32; ++i)//copy the n-1 block to the final
	{
		final[i] = bufout[i];
	}
	for (i = 0; i < 36; ++i)
	{
		printf("%02X", final[i]);
	}
	if (!memcmp(final, combine, 36))
	{
		printf("\nSignature is correct.");
	}
	getchar();
	return 0;
}