
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Lizard.h"
#include "randombytes.h"
#include "sha512.h"
#include "mat_mul.h"
#include <libkeccak.a.headers/SP800-185.h>

uint16_t seed[LWE_M * LWE_L1 * 2];
int count = 0;

#ifdef NOISE_D1
#define SAMPLE_DG Sample_D1
const uint16_t CDF_TABLE[9] = { 78, 226, 334, 425, 473, 495, 506, 510, 511 }; // out of [0, 511]
const size_t TABLE_LENGTH = 9;

uint16_t Sample_D1() {
	uint16_t rnd = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01ff;
	uint16_t sign = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D2
#define SAMPLE_DG Sample_D2
const uint16_t CDF_TABLE[4] = { 458, 946, 1020, 1023 }; // out of [0, 1023]
const size_t TABLE_LENGTH = 4;

uint16_t Sample_D2() {
	uint16_t rnd = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x03ff;
	uint16_t sign = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D3
#define SAMPLE_DG Sample_D3
const uint16_t CDF_TABLE[5] = { 151, 382, 482, 507, 511 }; // out of [0, 511]
const size_t TABLE_LENGTH = 5;

uint16_t Sample_D3() {
	uint16_t rnd = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01ff;
	uint16_t sign = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D4
#define SAMPLE_DG Sample_D4
const uint16_t CDF_TABLE[6] = { 121, 325, 445, 494, 508, 511 }; // out of [0, 511]
const size_t TABLE_LENGTH = 6;

uint16_t Sample_D4() {
	uint16_t rnd = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01ff;
	uint16_t sign = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D5
#define SAMPLE_DG Sample_D5
const uint16_t CDF_TABLE[12] = { 262, 761, 1188, 1518, 1748, 1892, 1974, 2016, 2035, 2043, 2046, 2047 }; // out of [0, 2047]
const size_t TABLE_LENGTH = 12;

uint16_t Sample_D5() {
	uint16_t rnd = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x07ff;
	uint16_t sign = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D6
#define SAMPLE_DG Sample_D6
const uint16_t CDF_TABLE[4] = { 380, 874, 1008, 1023 }; // out of [0, 1023]
const size_t TABLE_LENGTH = 4;

uint16_t Sample_D6() {
	uint16_t rnd = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x03ff;
	uint16_t sign = seed[count == LWE_M * LWE_L1 * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif

/**
  * @param	pk		[in] public key for encryption. pk = (A, B)
  * @param	sk		[in] private key for decryption sk = (S, T)
  */
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
	int i, j, k;
	uint8_t *sk_t = (uint8_t*)malloc(sizeof(uint8_t) * (LWE_N * LWE_L1));
	uint16_t *pk_A = (uint16_t*)malloc(sizeof(uint16_t) * (LWE_M * LWE_N));
	uint16_t *pk_B = (uint16_t*)malloc(sizeof(uint16_t) * (LWE_M * LWE_L1));

	// Generate a random matrix A
	randombytes((unsigned char*)pk_A, PublicKey_A);
	for (i = 0; i < LWE_M; ++i) {
		for (j = 0; j < LWE_N; ++j) {
			((uint16_t*)pk)[i * LWE_N + j] = pk_A[i * LWE_N + j] << _16_LOG_Q;
			((uint16_t*)pk)[i * LWE_N + j] = pk[(i * LWE_N * 2) + (j * 2)] << 8 | pk[(i * LWE_N * 2) + (j * 2 + 1)];
			pk_A[i*LWE_N + j] = pk_A[i*LWE_N + j] << _16_LOG_Q;
		}
	}

	// Generate a secret matrix S
	randombytes(sk_t, LWE_N * LWE_L1);
	// Secret distribution ZO(1/2)
#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY5_N1088)
	for (i = 0; i < LWE_N * LWE_L1; ++i) {
		if ((sk_t[i] & 0x03) == 0x00)
			sk[i] = -1;
		else if ((sk_t[i] & 0x03) == 0x01)
			sk[i] = 1;
		else
			sk[i] = 0;
	}
#endif
	// Secret distribution ZO(1/4)
#if defined(KEM_CATEGORY1_N663) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300)
	for (i = 0; i < LWE_N * LWE_L1; ++i) {
		if ((sk_t[i] & 0x07) == 0x00)
			sk[i] = -1;
		else if ((sk_t[i] & 0x07) == 0x01)
			sk[i] = 1;
		else
			sk[i] = 0;
	}
#endif

	// Generate a16 random matrix T
	randombytes(sk + LWE_N * LWE_L1, (LWE_L / 8));

	// Initialize B as an error matrix E
	randombytes((unsigned char*)seed, LWE_M * LWE_L1 * 2 * 2);
	for (i = 0; i < LWE_M; ++i) {
		for (j = 0; j < LWE_L1; ++j) {
			pk_B[i * LWE_L1 + j] = SAMPLE_DG() << _16_LOG_Q;
		}
	}



	//Add -AS to B. Resulting B = -AS + E
	//for (i = 0; i < LWE_M; ++i) {
	//	uint16_t* A_i = pk_A + LWE_N * i;
	//	uint16_t* B_i = pk_B + LWE_L1 * i;
	//	for (k = 0; k < LWE_N; ++k) {
	//		uint8_t* sk_k = sk + LWE_L1 * k;
	//		uint16_t A_ik = A_i[k]; // 
	//		//uint16_t A_ik = (uint16_t)((pk + LWE_N * 2 * i)[k * 2]) << 8 | (pk + LWE_N * 2 * i)[k * 2 + 1];
	//		//printf("A_ik= %d\n", A_ik);
	//		for (j = 0; j < LWE_L1; ++j) {
	//			//printf("sk_k[%d] = %d\n", j, sk_k[j]);
	//			B_i[j] -= A_ik * (char)sk_k[j];
	//			//printf("B_i[%d] = %d\n", j, B_i[j]);
	//		}
	//	}
	//}


	mul_a_s_add_e(pk_A, sk, pk_B, LWE_M, LWE_N, LWE_L1);



	for (i = 0; i < LWE_M; ++i) {
		for (j = 0; j < LWE_L1; ++j) {
			pk[PublicKey_A + (i * LWE_L1 * 2) + (j * 2)] = pk_B[i * LWE_L1 + j] >> 8;
			pk[PublicKey_A + (i * LWE_L1 * 2) + (j * 2 + 1)] = pk_B[i * LWE_L1 + j] & 0xff;
		}
	}

	free(sk_t);
	free(pk_A);
	free(pk_B);


	return 0;
}

/**
  * @param	ct		[out] data to be encrypted. ct = (c1, c2, d)
  * @param	ss		[out] shared secret
  * @param	pk		[in] public key for encryption. pk = (A, B)
  */
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, unsigned char *pk) {
	start = 0;
	start = clock();
	int i, j, k, hw = 0;

	//FILE *fp2, *fp3;
	//fp2 = fopen("değerler.txt", "w");
	//fp3 = fopen("bizimpk1.txt", "w");

	uint8_t r[LWE_M * LWE_L2] = { 0, };

	uint16_t c2[LWE_L1 * LWE_L2] = { 0, };
	uint16_t c1[LWE_N * LWE_L2] = { 0, };

	uint16_t *pk1 = malloc(LWE_M*LWE_N * sizeof(uint16_t));
	uint16_t *pk2 = malloc(LWE_L1*LWE_M * sizeof(uint16_t));


	uint64_t hash[LAMBDA / 16];
	uint64_t *hash_t = NULL;
	uint64_t M[LWE_L / 64];


	TupleElement tuple;
	unsigned char *S = "";

	// Generate a random matrix M
	randombytes((unsigned char*)M, LWE_L / 8);

	// Compute the matrix R = H(M)
	hash_t = (uint64_t *)calloc((LWE_M * LWE_L2) / 64, sizeof(uint64_t));
	tuple.input = (unsigned char*)M;
	tuple.inputBitLen = LWE_L;
	TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);

#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY1_N663) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300)
	i = 0;
	for (k = 0; k < LWE_L2; ++k) {
		hw = 0;
		uint8_t* r_t = r + k * LWE_M;
		while (hw < HR) {
			j = (uint16_t)hash_t[i] & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 10) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 12) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 22) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 24) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 34) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 36) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 46) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 48) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 58) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			i++;
			if (i == (LWE_M * LWE_L2) / 64) {
				i = 0;
				tuple.input = (unsigned char*)hash_t;
				tuple.inputBitLen = LWE_M * LWE_L2;
				TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);
			}
		}
		if (i == (LWE_M * LWE_L2) / 64) {
			i = 0;
			tuple.input = (unsigned char*)hash_t;
			tuple.inputBitLen = LWE_M * LWE_L2;
			TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);
		}
	}
#endif
#ifdef KEM_CATEGORY5_N1088
	i = 0;
	for (k = 0; k < LWE_L2; ++k) {
		hw = 0;
		uint8_t* r_t = r + k * LWE_M;
		while (hw < HR) {
			j = (uint16_t)hash_t[i] & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 11) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 13) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 24) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 26) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 37) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 39) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 50) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			i++;
			if (i == (LWE_M * LWE_L2) / 64) {
				i = 0;
				tuple.input = (unsigned char*)hash_t;
				tuple.inputBitLen = LWE_M * LWE_L2;
				TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);
			}
		}
		if (i == (LWE_M * LWE_L2) / 64) {
			i = 0;
			tuple.input = (unsigned char*)hash_t;
			tuple.inputBitLen = LWE_M * LWE_L2;
			TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);
		}
	}
#endif

	// Compute the vector d = H'(M)
	sha512((unsigned char*)M, LWE_L / 8, (unsigned char*)hash, LWE_L / 8);
#ifdef KEM_CATEGORY1_N663
	for (j = 0; j < 4; ++j) {
		ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + j * 8] = (unsigned char)(hash[j] >> 56);
		ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + j * 8 + 1] = (unsigned char)(hash[j] >> 48);
		ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + j * 8 + 2] = (unsigned char)(hash[j] >> 40);
		ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + j * 8 + 3] = (unsigned char)(hash[j] >> 32);
		ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + j * 8 + 4] = (unsigned char)(hash[j] >> 24);
		ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + j * 8 + 5] = (unsigned char)(hash[j] >> 16);
		ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + j * 8 + 6] = (unsigned char)(hash[j] >> 8);
		ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + j * 8 + 7] = (unsigned char)(hash[j] & 0xff);
	}

#endif
#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300) || defined(KEM_CATEGORY5_N1088)
	for (j = 0; j < LAMBDA / 32; ++j) {
		ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + j * 8] = (unsigned char)(hash[j] >> 56);
		ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + j * 8 + 1] = (unsigned char)(hash[j] >> 48);
		ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + j * 8 + 2] = (unsigned char)(hash[j] >> 40);
		ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + j * 8 + 3] = (unsigned char)(hash[j] >> 32);
		ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + j * 8 + 4] = (unsigned char)(hash[j] >> 24);
		ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + j * 8 + 5] = (unsigned char)(hash[j] >> 16);
		ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + j * 8 + 6] = (unsigned char)(hash[j] >> 8);
		ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + j * 8 + 7] = (unsigned char)(hash[j] & 0xff);
	}
#endif


	// Initialize c2 as q/2 * M
	for (i = 0; i < LAMBDA / 32; ++i) { for (j = 0; j < 64; ++j) { c2[64 * i + j] = ((uint16_t)(M[i] >> j)) << _16_LOG_T; } }

	for (i = 0; i < LWE_M; ++i) {
		for (j = 0; j < LWE_N; ++j) {
			pk1[i*LWE_N + j] = (pk[(LWE_N * 2 * i) + (j * 2)] << 8 | pk[(LWE_N * 2 * i) + (j * 2 + 1)]);
		}
		for (int k = 0; k < LWE_L1; ++k) {
			pk2[i*LWE_L1 + k] = (pk[PublicKey_A + (LWE_L1 * 2 * i) + (k * 2)] << 8 | pk[PublicKey_A + (LWE_L1 * 2 * i) + (k * 2 + 1)]);
		}
	}

	mul_aT_r_add_c(pk1, r, c1, LWE_M, LWE_N, LWE_L2);
	mul_aT_r_add_c2(pk2, r, c2, LWE_M, LWE_L1, LWE_L2);

	// Compute A^T * R and B^T * R, and then add to c1 and c2, respectively.
//for (k = 0; k < LWE_L2; k++) {
//	for (i = 0; i < LWE_M; ++i) {
//		//			for (j = 0; j < LWE_N; ++j) {
//		//				/*printf("pk[%d] = %x\n", (LWE_N * 2 * i) + (j * 2), pk[(LWE_N * 2 * i) + (j * 2)]);
//		//				printf("pk[%d] << 8 = %x\n", (LWE_N * 2 * i) + (j * 2), pk[(LWE_N * 2 * i) + (j * 2)] << 8);
//		//				printf("pk[%d] & 0xff = %x\n", (LWE_N * 2 * i) + (j * 2 + 1), pk[(LWE_N * 2 * i) + (j * 2 + 1)] & 0xff);
//		//				printf("out = %x\n", (pk[(LWE_N * 2 * i) + (j * 2)] << 8 | pk[(LWE_N * 2 * i) + (j * 2 + 1)] & 0xff));
//		//				printf("r[%d] = %x\n", k * LWE_M + i, r[k * LWE_M + i]);*/
//		//				c1[k * LWE_N + j] += (pk[(LWE_N * 2 * i) + (j * 2)] << 8 | pk[(LWE_N * 2 * i) + (j * 2 + 1)] & 0xff) * (char)r[k * LWE_M + i];
//		//				//printf("c1[%d] = %x\n", k * LWE_N + j, c1[k * LWE_N + j]);
//		//				/*fprintf(fp2, "pk1[%d] = %d", (LWE_N * 2 * i) + (j * 2), pk[(LWE_N * 2 * i) + (j * 2)]);
//		//				fprintf(fp2, "pk1[%d] = %d", (LWE_N * 2 * i) + (j * 2 + 1), pk[(LWE_N * 2 * i) + (j * 2 + 1)]);*/
//		//#ifdef yazdir
//		//				fprintf(fp2, "\nc1[%d] = pk[%d] | pk[%d] * r[%d] => %x = %x | %x *%x \n\r",k * LWE_N + j, (LWE_N * 2 * i) + (j * 2),
//		//					(LWE_N * 2 * i) + (j * 2 + 1), k * LWE_M + i, c1[k * LWE_N + j], pk[(LWE_N * 2 * i) + (j * 2)],
//		//					pk[(LWE_N * 2 * i) + (j * 2 + 1)] & 0xff, (uint16_t)r1[k * LWE_M + i]);
//		//#endif
//		//			}
//		for (j = 0; j < LWE_L1; ++j) {
//			c2[k * LWE_L1 + j] += (pk[PublicKey_A + (LWE_L1 * 2 * i) + (j * 2)] << 8 | pk[PublicKey_A + (LWE_L1 * 2 * i) + (j * 2 + 1)] & 0xff) * (char)r[k * LWE_M + i];
//			//c2[k * LWE_L1 + j] += pk[PublicKey_A + (LWE_L1 * 2 * i)] * (char)r[k * LWE_M + i];
//		}
//	}
//}

//fclose(fp1);

#ifdef yazdir
	if (memcmp(c3, c1, LWE_N*LWE_L2 * 2) == 0) {
		printf("Eşleşti\n");
	}
#endif	

	free(pk1);
	free(pk2);


	// Send c1 and c2 from mod q to mod p
	// Compute the shared secret K = G(c1, c2, d, M)
#ifdef KEM_CATEGORY1_N663
	for (i = 0; i < LWE_N * LWE_L2; ++i) {
		ct[i] = ((c1[i] + RD_ADD) & RD_AND) >> 8;
	}
	for (i = 0; i < LWE_L1 * LWE_L2; ++i) {
		ct[LWE_N * LWE_L2 + i] = ((c2[i] + RD_ADD) & RD_AND) >> 8;
	}

	hash_t = (uint64_t *)calloc(((LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4) + 32) / 8, sizeof(uint64_t));
	memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4));
	memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4), (unsigned char*)M, 32);
	sha512((unsigned char*)hash_t, (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4) + 32, (unsigned char*)hash, 32);
#endif
#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300) || defined(KEM_CATEGORY5_N1088)
	for (i = 0; i < LWE_N * LWE_L2; ++i) {
		c1[i] = (c1[i] + RD_ADD) & RD_AND;
		ct[i * 2] = c1[i] >> 8;
		ct[i * 2 + 1] = c1[i] & 0xff;
	}
	for (i = 0; i < LWE_L1 * LWE_L2; ++i) {
		c2[i] = (c2[i] + RD_ADD) & RD_AND;
		ct[(LWE_N * LWE_L2 * 2) + i * 2] = c2[i] >> 8;
		ct[(LWE_N * LWE_L2 * 2) + i * 2 + 1] = c2[i] & 0xff;
	}

	hash_t = (uint64_t *)calloc(((LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4)) / 8, sizeof(uint64_t));
	memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4));
	memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4), (unsigned char*)M, (LAMBDA / 4));
	sha512((unsigned char*)hash_t, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4), (unsigned char*)hash, (LAMBDA / 4));
#endif

	for (i = 0; i < LAMBDA / 32; ++i) {
		ss[i * 8] = (unsigned char)(hash[i] >> 56);
		ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
		ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
		ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
		ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
		ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
		ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
		ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
	}

	free(hash_t);

	finish = clock();
	elapsed1 += (finish - start);


	return 0;
}

/**
  * @param	ss		[out] shared secret
  * @param	ct		[in] encrypted data  ct = (c1, c2, d)
  * @param	sk		[in] private/public key for decryption. sk = (S, T), pk = (A, B)
  */
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
	start = clock();
	int res = 0;
	int i, j, k, hw = 0;

	uint8_t r[LWE_M * LWE_L2] = { 0, };

	uint16_t decomp_M[LWE_L1 * LWE_L2] = { 0, };
	uint16_t c2[LWE_L1 * LWE_L2] = { 0, };
	uint16_t c1[LWE_N * LWE_L2] = { 0, };
	size_t neg_start[LWE_L2] = { 0, };

	uint64_t M[LWE_L / 64] = { 0, };
	uint64_t d[LAMBDA / 32];
	uint64_t hash[LAMBDA / 32];
	uint64_t *hash_t = NULL;

	TupleElement tuple;
	unsigned char *S = "";


	uint16_t *sk1 = malloc(LWE_M*(LWE_N+LWE_L1) * sizeof(uint16_t));


#ifdef KEM_CATEGORY1_N663
	for (i = 0; i < LWE_L1 * LWE_L2; ++i) { decomp_M[i] = ct[LWE_N * LWE_L2 + i] << 8; } // Initialize M as c2
	// Compute M = (M + S^T * c1)
	for (k = 0; k < LWE_L2; ++k) {
		for (i = 0; i < LWE_N; ++i) {
			uint16_t ctx_ai = ct[k * LWE_N + i] << 8;
			for (j = 0; j < LWE_L1; ++j) {
				decomp_M[LWE_L1 * k + j] += ctx_ai * (char)sk[LWE_L1 * i + j];
			}
		}
	}
#endif
#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300) || defined(KEM_CATEGORY5_N1088)
	for (i = 0; i < LWE_L2 * LWE_L1; ++i) { decomp_M[i] = ct[(LWE_N * LWE_L2 * 2) + i * 2] << 8 | ct[(LWE_N * LWE_L2 * 2) + i * 2 + 1] & 0xff; } // Initialize M as c2
	// Compute M = (M + S^T * c1)
	for (k = 0; k < LWE_L2; ++k) {
		for (i = 0; i < LWE_N; ++i) {
			uint16_t ctx_ai = ct[(k * LWE_N * 2) + i * 2] << 8 | ct[(k * LWE_N * 2) + i * 2 + 1] & 0xff;
			for (j = 0; j < LWE_L1; ++j) {
				decomp_M[LWE_L1 * k + j] += ctx_ai * (char)sk[LWE_L1 * i + j];
			}
		}
	}

	/*uint16_t *ctx_ai = malloc(LWE_L2*LWE_N * sizeof(uint16_t));
	for (k = 0; k < LWE_N; ++k) {
		for (i = 0; i < LWE_L2; ++i) {
			ctx_ai[k*LWE_L2 + i] = ct[(k * LWE_L2 * 2) + i * 2] << 8 | ct[(k * LWE_L2 * 2) + i * 2 + 1];
		}
	}
	mul_m_s_add_e(ctx_ai, sk, decomp_M, LWE_N, LWE_L2, LWE_L1);*/

#endif




	// Compute M = 2/p * M
	for (i = 0; i < LWE_L1 * LWE_L2; ++i) {
		decomp_M[i] += DEC_ADD;
		decomp_M[i] >>= _16_LOG_T;
	}

	// Set M
	for (i = 0; i < LAMBDA / 32; ++i) {
		for (j = 0; j < 64; ++j) {
			uint64_t a = ((uint64_t)decomp_M[64 * i + j]) << j;
			M[i] ^= a;
		}
	}

	// Compute the matrix R = H(M)
	hash_t = (uint64_t *)calloc((LWE_M * LWE_L2) / 64, sizeof(uint64_t));
	tuple.input = (unsigned char*)M;
	tuple.inputBitLen = LAMBDA * 2;
	TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);

#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY1_N663) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300)
	i = 0;
	for (k = 0; k < LWE_L2; ++k) {
		hw = 0;
		uint8_t* r_t = r + k * LWE_M;
		while (hw < HR) {
			j = (uint16_t)hash_t[i] & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 10) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 12) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 22) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 24) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 34) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 36) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 46) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 48) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 58) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			i++;
			if (i == (LWE_M * LWE_L2) / 64) {
				i = 0;
				tuple.input = (unsigned char*)hash_t;
				tuple.inputBitLen = LWE_M * LWE_L2;
				TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);
			}
		}
		if (i == (LWE_M * LWE_L2) / 64) {
			i = 0;
			tuple.input = (unsigned char*)hash_t;
			tuple.inputBitLen = LWE_M * LWE_L2;
			TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);
		}
	}
#endif
#ifdef KEM_CATEGORY5_N1088
	i = 0;
	for (k = 0; k < LWE_L2; ++k) {
		hw = 0;
		uint8_t* r_t = r + k * LWE_M;
		while (hw < HR) {
			j = (uint16_t)hash_t[i] & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 11) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 13) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 24) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 26) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 37) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			j = (uint16_t)(hash_t[i] >> 39) & (LWE_M - 1);
			if (r_t[j] == 0) {
				r_t[j] = ((uint16_t)(hash_t[i] >> 50) & 0x02) - 1;
				hw++;
				if (hw == HR) {
					i++;
					break;
				}
			}
			i++;
			if (i == (LWE_M * LWE_L2) / 64) {
				i = 0;
				tuple.input = (unsigned char*)hash_t;
				tuple.inputBitLen = LWE_M * LWE_L2;
				TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);
			}
		}
		if (i == (LWE_M * LWE_L2) / 64) {
			i = 0;
			tuple.input = (unsigned char*)hash_t;
			tuple.inputBitLen = LWE_M * LWE_L2;
			TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_M * LWE_L2, S, strlen(S) * 8);
		}
	}
#endif

	// Compute the vector d' = H'(M)
	sha512((unsigned char*)M, LAMBDA / 4, (unsigned char*)hash, LAMBDA / 4);

	// Initialize c2' as q/2 * M
	for (i = 0; i < LWE_L1 * LWE_L2; ++i) { c2[i] = decomp_M[i] << _16_LOG_T; }

	for (i = 0; i < LWE_M; ++i) {
		for (j = 0; j < LWE_N+LWE_L1; ++j) {
			sk1[i*(LWE_N+LWE_L1) + j] = (sk[CRYPTO_SECRETKEYBYTES + ((LWE_N+LWE_L1) * 2 * i) + (j * 2)] << 8 | sk[CRYPTO_SECRETKEYBYTES + ((LWE_N + LWE_L1) * 2 * i) + (j * 2 + 1)]);
		}
	}

	mul_aT_r_add_c(sk1, r, c1, LWE_M, LWE_N, LWE_L2);
	mul_aT_r_add_c2(sk1+(LWE_M*LWE_N), r, c2, LWE_M, LWE_L1, LWE_L2);


	// Compute A^T * R and B^T * R, and then add to c1' and c2', respectively.
	/*for (k = 0; k < LWE_L2; k++) {
		for (i = 0; i < LWE_M; ++i) {
			for (j = 0; j < LWE_N; ++j) {
				c1[k * LWE_N + j] += (sk[CRYPTO_SECRETKEYBYTES + (LWE_N * 2 * i) + (j * 2)] << 8
					| sk[CRYPTO_SECRETKEYBYTES + (LWE_N * 2 * i) + (j * 2 + 1)] & 0xff) * (char)r[k * LWE_M + i];
			}
			for (j = 0; j < LWE_L1; ++j) {
				c2[k * LWE_L1 + j] += (sk[CRYPTO_SECRETKEYBYTES + PublicKey_A + (LWE_L1 * 2 * i) + (j * 2)] << 8
					| sk[CRYPTO_SECRETKEYBYTES + PublicKey_A + (LWE_L1 * 2 * i) + (j * 2 + 1)] & 0xff) * (char)r[k * LWE_M + i];
			}
		}
	}*/

	// Send c1' and c2' from mod q to mod p
	for (i = 0; i < LWE_N * LWE_L2; ++i)
		c1[i] = ((c1[i] + RD_ADD) & RD_AND);
	for (i = 0; i < LWE_L1 * LWE_L2; ++i)
		c2[i] = ((c2[i] + RD_ADD) & RD_AND);

	// Set d
#ifdef KEM_CATEGORY1_N663
	for (i = 0; i < LAMBDA / 32; ++i) {
		d[i] = (((uint64_t)(ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + i * 8] & 0xff) << 56) + ((uint64_t)(ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + i * 8 + 1] & 0xff) << 48)
			+ ((uint64_t)(ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + i * 8 + 2] & 0xff) << 40) + ((uint64_t)(ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + i * 8 + 3] & 0xff) << 32)
			+ ((uint64_t)(ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + i * 8 + 4] & 0xff) << 24) + ((uint64_t)(ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + i * 8 + 5] & 0xff) << 16)
			+ ((uint64_t)(ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + i * 8 + 6] & 0xff) << 8) + ((uint64_t)ct[(LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + i * 8 + 7] & 0xff));
	}
#endif
#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300) || defined(KEM_CATEGORY5_N1088)
	for (i = 0; i < LAMBDA / 32; ++i) {
		d[i] = (((uint64_t)(ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + i * 8] & 0xff) << 56) + ((uint64_t)(ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + i * 8 + 1] & 0xff) << 48)
			+ ((uint64_t)(ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + i * 8 + 2] & 0xff) << 40) + ((uint64_t)(ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + i * 8 + 3] & 0xff) << 32)
			+ ((uint64_t)(ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + i * 8 + 4] & 0xff) << 24) + ((uint64_t)(ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + i * 8 + 5] & 0xff) << 16)
			+ ((uint64_t)(ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + i * 8 + 6] & 0xff) << 8) + ((uint64_t)ct[(LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + i * 8 + 7] & 0xff));
	}
#endif	
	// If d ≠ d', then compute K = G(c1, c2, d, T)
#ifdef KEM_CATEGORY1_N663
	if ((hash[0] != d[0]) || (hash[1] != d[1]) || (hash[2] != d[2]) || (hash[3] != d[3])) {
		hash_t = (uint64_t *)calloc((LWE_N * LWE_L2 + LWE_L1 * LWE_L2 + (LAMBDA / 4) + 32) / 8, sizeof(uint64_t));

		memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4), sk + LWE_N * LWE_L1, 32);
		sha512((unsigned char*)hash_t, (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4) + 32, (unsigned char*)hash, 32);

		for (j = 0; j < 4; ++j) {
			ss[j * 8] = (unsigned char)(hash[j] >> 56);
			ss[j * 8 + 1] = (unsigned char)(hash[j] >> 48);
			ss[j * 8 + 2] = (unsigned char)(hash[j] >> 40);
			ss[j * 8 + 3] = (unsigned char)(hash[j] >> 32);
			ss[j * 8 + 4] = (unsigned char)(hash[j] >> 24);
			ss[j * 8 + 5] = (unsigned char)(hash[j] >> 16);
			ss[j * 8 + 6] = (unsigned char)(hash[j] >> 8);
			ss[j * 8 + 7] = (unsigned char)(hash[j] & 0xff);
		}
		return res = 1;
	}
#endif
#ifdef KEM_CATEGORY1_N536
	if ((hash[0] != d[0]) || (hash[1] != d[1]) || (hash[2] != d[2]) || (hash[3] != d[3])) {
		hash_t = (uint64_t *)calloc(((LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + 32) / 8, sizeof(uint64_t));

		memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4), sk + LWE_N * LWE_L1, 32);
		sha512((unsigned char*)hash_t, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + 32, (unsigned char*)hash, 32);

		for (j = 0; j < 4; ++j) {
			ss[j * 8] = (unsigned char)(hash[j] >> 56);
			ss[j * 8 + 1] = (unsigned char)(hash[j] >> 48);
			ss[j * 8 + 2] = (unsigned char)(hash[j] >> 40);
			ss[j * 8 + 3] = (unsigned char)(hash[j] >> 32);
			ss[j * 8 + 4] = (unsigned char)(hash[j] >> 24);
			ss[j * 8 + 5] = (unsigned char)(hash[j] >> 16);
			ss[j * 8 + 6] = (unsigned char)(hash[j] >> 8);
			ss[j * 8 + 7] = (unsigned char)(hash[j] & 0xff);
		}

		return res = 1;
	}
#endif
#if defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952)
	if ((hash[0] != d[0]) || (hash[1] != d[1]) || (hash[2] != d[2]) || (hash[3] != d[3]) || (hash[4] != d[4]) || (hash[5] != d[5])) {
		hash_t = (uint64_t *)calloc(((LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4)) / 8, sizeof(uint64_t));

		memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4), sk + LWE_N * LWE_L1, LAMBDA / 4);
		sha512((unsigned char*)hash_t, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4), (unsigned char*)hash, LAMBDA / 4);

		for (i = 0; i < LAMBDA / 32; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}

		return res = 1;
	}
#endif
#if defined(KEM_CATEGORY5_N1300) || defined(KEM_CATEGORY5_N1088)
	if ((hash[0] != d[0]) || (hash[1] != d[1]) || (hash[2] != d[2]) || (hash[3] != d[3])
		|| (hash[4] != d[4]) || (hash[5] != d[5]) || (hash[6] != d[6]) || (hash[7] != d[7])) {
		hash_t = (uint64_t *)calloc(((LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4)) / 8, sizeof(uint64_t));

		memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4), sk + LWE_N * LWE_L1, LAMBDA / 4);
		sha512((unsigned char*)hash_t, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4), (unsigned char*)hash, LAMBDA / 4);

		for (i = 0; i < LAMBDA / 32; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}

		return res = 1;
	}
#endif

	// If (c1, c2) ≠ (c1, c2'), then compute K = G(c1, c2, d, T). 
	// Else the shared secret K = G(c1, c2, d, M)
#ifdef KEM_CATEGORY1_N663
	for (i = 0; i < LWE_N * LWE_L2; ++i) {
		if (c1[i] >> 8 != ct[i]) {
			res = 2;
			break;
		}
	}
	for (i = 0; i < LWE_L1 * LWE_L2; ++i) {
		if (c2[i] >> 8 != ct[LWE_N * LWE_L2 + i]) {
			res = 2;
			break;
		}
	}

	if (res == 2) {
		hash_t = (uint64_t *)calloc((LWE_N * LWE_L2 + LWE_L1 * LWE_L2 + (LAMBDA / 4) + 32) / 8, sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4), sk + LWE_N * LWE_L1, 32);
		sha512((unsigned char*)hash_t, (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4) + 32, (unsigned char*)hash, 32);

		for (i = 0; i < 4; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}
	}
	else {
		hash_t = (uint64_t *)calloc((LWE_N * LWE_L2 + LWE_L1 * LWE_L2 + (LAMBDA / 4) + 32) / 8, sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4), (unsigned char*)M, 32);
		sha512((unsigned char*)hash_t, (LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4) + 32, (unsigned char*)hash, 32);

		for (i = 0; i < 4; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}
	}
#endif
#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300) || defined(KEM_CATEGORY5_N1088)
	for (i = 0; i < LWE_N * LWE_L2; ++i) {
		if (c1[i] != ((ct[i * 2] & 0xff) << 8 | ct[i * 2 + 1] & 0xff)) {
			res = 2;
			break;
		}
	}
	for (i = 0; i < LWE_L1 * LWE_L2; ++i) {
		if (c2[i] != ((ct[(LWE_N * LWE_L2 * 2) + i * 2] & 0xff) << 8 | ct[(LWE_N * LWE_L2 * 2) + i * 2 + 1] & 0xff)) {
			res = 2;
			break;
		}
	}

	if (res == 2) {
		hash_t = (uint64_t *)calloc(((LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4)) / 8, sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4), sk + LWE_N * LWE_L1, (LAMBDA / 4));
		sha512((unsigned char*)hash_t, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4), (unsigned char*)hash, (LAMBDA / 4));

		for (i = 0; i < LAMBDA / 32; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}
	}
	else {
		hash_t = (uint64_t *)calloc(((LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4)) / 8, sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, ct, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4), (unsigned char*)M, (LAMBDA / 4));
		sha512((unsigned char*)hash_t, (LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4) + (LAMBDA / 4), (unsigned char*)hash, (LAMBDA / 4));

		for (i = 0; i < LAMBDA / 32; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}
	}
#endif

	finish = clock();
	elapsed2 += (finish - start);

	free(hash_t);
	free(sk1);
	return res;
}
