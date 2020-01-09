//


#include "mat_mul.h"
#include <stdlib.h>
#include "stdio.h"
#include <stdint.h>

void mul_a_s_add_e(uint16_t *pk, unsigned char *sk, uint16_t *out, int n, int n1, int n_bar) {


	int l = n % 4;
	int z = 0;
	int i, j, k;
	uint16_t *sk_t;
	sk_t = malloc(n1*n_bar * sizeof(uint16_t));

	for (i = 0; i < n1; i++) {
		for (k = 0; k < n_bar; k++) {

			sk_t[k*n1 + i] = sk[i*n_bar + k];

		}
	}

	for (i = 0; i < n - l; i += 4) {
		for (k = 0; k < n_bar; k++) {
			uint16_t sum[4] = { 0 };
			for (j = 0; j < n1; j++) {
				uint16_t sp = sk_t[k*n1 + j];


				sum[0] += pk[(i + 0) * (n1)+j + z] * (char)sp;
				sum[1] += pk[(i + 1) * (n1)+j + z] * (char)sp;
				sum[2] += pk[(i + 2) * (n1)+j + z] * (char)sp;
				sum[3] += pk[(i + 3) * (n1)+j + z] * (char)sp;

			}

			out[(i + 0)*n_bar + k] -= sum[0];
			out[(i + 2)*n_bar + k] -= sum[2];
			out[(i + 1)*n_bar + k] -= sum[1];
			out[(i + 3)*n_bar + k] -= sum[3];


		}
	}

	/*if (n % 4 != 0) {
		for (int t = 0; t < l*n_bar; t += n_bar) {
			for (k = 0; k < n_bar; k++) {
				uint16_t sum[1] = { 0 };
				for (j = 0; j < n1; j++) {
					uint16_t sp = sk_t[k*n1 + j];
					sum[0] += pk[0 * n1 + j + z] * sp;
				}
				out[i*n_bar + k + t] += sum[0];
			}
			z += n1;
		}
	}*/

	free(sk_t);
}

void mul_aT_r_add_c(uint16_t *pk, uint8_t *r, uint16_t *out, int n, int n1, int n_bar) {

	int l = n1 % 4;
	int z = 0;
	int i, j, k;
	uint16_t *pk_t;
	//uint8_t *r_t;


	//FILE *fp1;
	//fp1 = fopen("bizim_degerler.txt", "w");
	//fp2 = fopen("bizimpk1.txt", "w");

	pk_t = malloc(n*n1 * sizeof(uint16_t));
	//r_t = calloc(n1*n_bar, sizeof(uint8_t));

	for (i = 0; i < n; i++) {
		for (k = 0; k < n1; k++) {

			pk_t[k*n + i] = pk[i*n1 + k];


		}
	}

	/*for (i = 0; i < n; i++) {
		for (k = 0; k < n_bar; k++) {

			r_t[k*n + i] = r[i*n_bar + k];

		}
	}*/

	/*for (int i = 0; i < n*n1; i++) {
		fprintf(fp2, "pk1[%d] = %d\n", i, pk[i]);
	}*/

	for (i = 0; i < n1 - l; i += 4) {
		for (k = 0; k < n_bar; k++) {
			uint16_t sum[4] = { 0 };
			for (j = 0; j < n; j++) {
				uint16_t sp = (char)r[k*n + j];

#ifdef yazdir
				fprintf(fp1, "\nr[%d] = %x\n\r", k*n + j, r[k*n + j]);

				fprintf(fp1, "\npk[%d] = %x\n\r", (i + 0) * (n)+j, pk_t[(i + 0) * (n)+j]);
				fprintf(fp1, "\npk[%d] = %x\n\r", (i + 1) * (n)+j, pk_t[(i + 1) * (n)+j]);
				fprintf(fp1, "\npk[%d] = %x\n\r", (i + 2) * (n)+j, pk_t[(i + 2) * (n)+j]);
				fprintf(fp1, "\npk[%d] = %x\n\r", (i + 3) * (n)+j, pk_t[(i + 3) * (n)+j]);
#endif
				sum[0] += pk_t[(i + 0) * (n)+j] * sp;
				sum[1] += pk_t[(i + 1) * (n)+j] * sp;
				sum[2] += pk_t[(i + 2) * (n)+j] * sp;
				sum[3] += pk_t[(i + 3) * (n)+j] * sp;

				/*sum[0] += pk[(i + 0) + (n1)*j] * sp;
				sum[1] += pk[(i + 1) + (n1)*j] * sp;
				sum[2] += pk[(i + 2) + (n1)*j] * sp;
				sum[3] += pk[(i + 3) + (n1)*j] * sp;*/

				/*fprintf(fp1, "\nsum[%d] = %x\n\r", 0, sum[0]);
				fprintf(fp1, "\nsum[%d] = %x\n\r", 1, sum[1]);
				fprintf(fp1, "\nsum[%d] = %x\n\r", 2, sum[2]);
				fprintf(fp1, "\nsum[%d] = %x\n\r", 3, sum[3]);*/


			}

			/*out[(i + 0)*n_bar + k] += sum[0];
			out[(i + 1)*n_bar + k] += sum[1];
			out[(i + 2)*n_bar + k] += sum[2];
			out[(i + 3)*n_bar + k] += sum[3];*/


			out[k*n1 + (i + 0)] += sum[0];
			out[k*n1 + (i + 1)] += sum[1];
			out[k*n1 + (i + 2)] += sum[2];
			out[k*n1 + (i + 3)] += sum[3];
#ifdef yazdir
			fprintf(fp1, "\n\n**************************\n\r");
			fprintf(fp1, "\nout[%d] = %x\n\r", k*n + (i + 0), out[k*n + (i + 0)]);
			fprintf(fp1, "\nout[%d] = %x\n\r", k*n + (i + 1), out[k*n + (i + 1)]);
			fprintf(fp1, "\nout[%d] = %x\n\r", k*n + (i + 2), out[k*n + (i + 2)]);
			fprintf(fp1, "\nout[%d] = %x\n\r", k*n + (i + 3), out[k*n + (i + 3)]);
#endif
			/*fprintf(fp1, "\n\n**************************\n\r");
			fprintf(fp1, "\nout[%d] = %x\n\r", (i + 0)*n_bar + k, out[(i + 0)*n_bar + k]);
			fprintf(fp1, "\nout[%d] = %x\n\r", (i + 1)*n_bar + k, out[(i + 1)*n_bar + k]);
			fprintf(fp1, "\nout[%d] = %x\n\r", (i + 2)*n_bar + k, out[(i + 2)*n_bar + k]);
			fprintf(fp1, "\nout[%d] = %x\n\r", (i + 3)*n_bar + k, out[(i + 3)*n_bar + k]);*/


		}
		//z += (n1) * 4;
	}

	/*if (n1 % 4 != 0) {
		for (int t = 0; t < l*n_bar; t += n_bar) {
			for (k = 0; k < n_bar; k++) {
				uint16_t sum[1] = { 0 };
				for (j = 0; j < n; j++) {
					uint16_t sp = r[k*n + j];
					sum[0] += pk_t[0 * n + j + z] * sp;
				}
				out[i*n_bar + k + t] += sum[0];
			}
			z += n;
		}
	}*/

	/*for (int i = 0; i < n*n_bar; i++) {
		fprintf(fp1, "c1[%d] = %d \n", i, out[i]);
	}*/


	free(pk_t);
	//free(r_t);
	//fclose(fp1);
	//fclose(fp2);
}

void mul_aT_r_add_c2(uint16_t *pk, uint8_t *r, uint16_t *out, int n, int n1, int n_bar) {

	int l = n1 % 4;
	int z = 0;
	int i, j, k;
	uint16_t *pk_t;

	pk_t = malloc(n*n1 * sizeof(uint16_t));

	for (i = 0; i < n; i++) {
		for (k = 0; k < n1; k++) {

			pk_t[k*n + i] = pk[i*n1 + k];


		}
	}

	for (i = 0; i < n1 - l; i += 4) {
		for (k = 0; k < n_bar; k++) {
			uint16_t sum[4] = { 0 };
			for (j = 0; j < n; j++) {
				uint16_t sp = (char)r[k*n + j];

#ifdef yazdir
				fprintf(fp1, "\nr[%d] = %x\n\r", k*n + j, r[k*n + j]);

				fprintf(fp1, "\npk[%d] = %x\n\r", (i + 0) * (n)+j, pk_t[(i + 0) * (n)+j]);
				fprintf(fp1, "\npk[%d] = %x\n\r", (i + 1) * (n)+j, pk_t[(i + 1) * (n)+j]);
				fprintf(fp1, "\npk[%d] = %x\n\r", (i + 2) * (n)+j, pk_t[(i + 2) * (n)+j]);
				fprintf(fp1, "\npk[%d] = %x\n\r", (i + 3) * (n)+j, pk_t[(i + 3) * (n)+j]);
#endif
				sum[0] += pk_t[(i + 0) * (n)+j] * sp;
				sum[1] += pk_t[(i + 1) * (n)+j] * sp;
				sum[2] += pk_t[(i + 2) * (n)+j] * sp;
				sum[3] += pk_t[(i + 3) * (n)+j] * sp;

			}

			/*out[(i + 0)*n_bar + k] += sum[0];
			out[(i + 1)*n_bar + k] += sum[1];
			out[(i + 2)*n_bar + k] += sum[2];
			out[(i + 3)*n_bar + k] += sum[3];*/


			out[k*n1 + (i + 0)] += sum[0];
			out[k*n1 + (i + 1)] += sum[1];
			out[k*n1 + (i + 2)] += sum[2];
			out[k*n1 + (i + 3)] += sum[3];
#ifdef yazdir
			fprintf(fp1, "\n\n**************************\n\r");
			fprintf(fp1, "\nout[%d] = %x\n\r", k*n + (i + 0), out[k*n + (i + 0)]);
			fprintf(fp1, "\nout[%d] = %x\n\r", k*n + (i + 1), out[k*n + (i + 1)]);
			fprintf(fp1, "\nout[%d] = %x\n\r", k*n + (i + 2), out[k*n + (i + 2)]);
			fprintf(fp1, "\nout[%d] = %x\n\r", k*n + (i + 3), out[k*n + (i + 3)]);
#endif

		}
	}

	/*if (n1 % 4 != 0) {
		for (int t = 0; t < l*n_bar; t += n_bar) {
			for (k = 0; k < n_bar; k++) {
				uint16_t sum[1] = { 0 };
				for (j = 0; j < n; j++) {
					uint16_t sp = r[k*n + j];
					sum[0] += pk_t[0 * n + j + z] * sp;
				}
				out[i*n_bar + k + t] += sum[0];
			}
			z += n;
		}
	}*/



	free(pk_t);
	//fclose(fp1);
}

void mul_m_s_add_e(uint16_t *pk, const unsigned char *sk, uint16_t *out, int n, int n1, int n_bar) {

	int l = n % 4;
	int z = 0;
	int i, j, k;
	uint16_t *sk_t;
	sk_t = malloc(n1*n_bar * sizeof(uint16_t));

	for (i = 0; i < n1; i++) {
		for (k = 0; k < n_bar; k++) {

			sk_t[k*n1 + i] = sk[i*n_bar + k];

		}
	}

	for (i = 0; i < n - l; i += 4) {
		for (k = 0; k < n_bar; k++) {
			uint16_t sum[4] = { 0 };
			for (j = 0; j < n1; j++) {
				uint16_t sp = sk_t[k*n1 + j];


				sum[0] += pk[(i + 0) * (n1)+j + z] * (char)sp;
				sum[1] += pk[(i + 1) * (n1)+j + z] * (char)sp;
				sum[2] += pk[(i + 2) * (n1)+j + z] * (char)sp;
				sum[3] += pk[(i + 3) * (n1)+j + z] * (char)sp;

			}

			out[(i + 0)*n_bar + k] -= sum[0];
			out[(i + 2)*n_bar + k] -= sum[2];
			out[(i + 1)*n_bar + k] -= sum[1];
			out[(i + 3)*n_bar + k] -= sum[3];


		}
	}

	/*if (n % 4 != 0) {
	for (int t = 0; t < l*n_bar; t += n_bar) {
	for (k = 0; k < n_bar; k++) {
	uint16_t sum[1] = { 0 };
	for (j = 0; j < n1; j++) {
	uint16_t sp = sk_t[k*n1 + j];
	sum[0] += pk[0 * n1 + j + z] * sp;
	}
	out[i*n_bar + k + t] += sum[0];
	}
	z += n1;
	}
	}*/

	free(sk_t);
}
