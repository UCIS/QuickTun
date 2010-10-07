#include "crypto_box.h"

int main() {
	unsigned char n[crypto_box_NONCEBYTES];
	unsigned char m[32+crypto_box_ZEROBYTES];
	unsigned char c[32+crypto_box_ZEROBYTES];

	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	//crypto_box_keypair(pk, sk);
	//randombytes(sk,32);
	sk[0]=1;
	crypto_scalarmult_curve25519_base(pk,sk);


	int r;

	unsigned char* buffer1offset = m + crypto_box_ZEROBYTES;

	strcpy(buffer1offset, "hello world");
	printf("in=$s\n", buffer1offset);
	memset(m, 0, crypto_box_ZEROBYTES);
	r=crypto_box(c, m, 32+crypto_box_ZEROBYTES, n, pk, sk);
	printf("ret=%d\n", r);

	memset(c, 0, crypto_box_BOXZEROBYTES);
	r=crypto_box_open(m, c, 32+crypto_box_ZEROBYTES, n, pk, sk);
	printf("ret=%d\n", r);
	printf("out=$s\n", buffer1offset);
}
