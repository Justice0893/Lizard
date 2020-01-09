#ifndef MAT_MUL_H
#define MAT_MUL_H

#include <stdint.h>

void mul_a_s_add_e(uint16_t *pk, unsigned char *sk, uint16_t *out,int n,int n1,int n_bar);

void mul_aT_r_add_c(uint16_t *pk, uint8_t *r ,uint16_t *out, int n, int n1,int n_bar);

void mul_aT_r_add_c2(uint16_t *pk, uint8_t *r ,uint16_t *out, int n, int n1,int n_bar);

void mul_m_s_add_e(uint16_t *pk, const unsigned char *sk, uint16_t *out,int n,int n1,int n_bar);
#endif
