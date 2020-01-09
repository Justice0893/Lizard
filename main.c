#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "Lizard.h"

PublicKey pk;
SecretKey sk;
unsigned char sk_t[CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES];

void Keygen_kem_CCA() {
	elapsed1 = clock();
	for (int l = 0; l < iter; ++l) {
		crypto_kem_keypair(pk, sk);
	}
	elapsed1 = clock() - elapsed1;

	printf("    Keygen Time: %f ms\n", elapsed1 * 1000. / CLOCKS_PER_SEC / iter);
}

void EncDecTest_kem_CCA() {
	unsigned char ss1[CRYPTO_BYTES];
	unsigned char ss2[CRYPTO_BYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	
	memcpy(sk_t, sk, sizeof(unsigned char) * CRYPTO_SECRETKEYBYTES);
	memcpy(sk_t + CRYPTO_SECRETKEYBYTES, pk, sizeof(unsigned char) * CRYPTO_PUBLICKEYBYTES);

	int i, l, res = 0;

	elapsed1 = 0;
	elapsed2 = 0;

	for (l = 0; l < iter; ++l) {
		
		for (i = 0; i < testnum; i++){
			crypto_kem_enc(ct, ss1, pk);
			res = crypto_kem_dec(ss2, ct, sk_t);
		}

		if (res == 1) {
			printf("    Decryption Validity Error Type 1 : d components\n");
			break;
		}

		if (res == 2) {
			printf("    Decryption Validity Error Type 2 : c1, c2 components\n");
			break;
		}

		// Correctness check
		for (i = 0; i < LAMBDA / 4; ++i) {
			if (ss1[i] != ss2[i]) {
				printf("    Correctness Error\n");
				break;
			}
		}
		if (i < LAMBDA / 4) break;
	}
	printf("    Enc Time: %f ms\n", elapsed1 * 1000. / CLOCKS_PER_SEC / testnum / iter);
	printf("    Dec Time: %f ms\n", elapsed2 * 1000. / CLOCKS_PER_SEC / testnum / iter);
}

void main() {
	printf("\n  //////////////////////////////////////////////////////////////////\n\n");
	printf("\t\t"PARAMNAME" Parameter\n\n");
	printf("    LWE dimension: %d, \t\tLWR dimension: %d\n", LWE_N, LWE_M);
	printf("    Plaintext dimension: %d, \t\tPlaintext Modulus: %d bits\t\n", LWE_L, LOG_T);
	printf("    Public Key modulus: %d bits, \tCiphertext modulus: %d bits\t\n\n", LOG_Q, LOG_P);
	printf("  //////////////////////////////////////////////////////////////////\n\n");
	printf("\t\t\tPerformance Test\n\n");

	// Key Generation
	KEYGEN();

	// Enc and Dec
	ENCDECTEST();
}