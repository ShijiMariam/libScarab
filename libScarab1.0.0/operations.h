#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include<math.h>
#include "integer-fhe.h"

#define WORDLEN 32
#define WORDSIZE 4294967296

void memAlloc(mpz_t **);

void decimalToBinary(int[], int);

int binaryToDecimal(int[]);

void binary_print(int[]);

void cipher_print(mpz_t*);

void fhe_wordEncrypt(mpz_t*, fhe_pk_t, int[]);

void fhe_wordDecrypt(int[], fhe_sk_t, mpz_t*);

void fhe_NOT(mpz_t, mpz_t, fhe_pk_t);

void fhe_OR(mpz_t, mpz_t, mpz_t, fhe_pk_t);

void fhe_XOR(mpz_t, mpz_t, mpz_t, fhe_pk_t);

void fhe_AND(mpz_t, mpz_t, mpz_t, fhe_pk_t);

void fhe_logicalNOT(mpz_t*, mpz_t*, fhe_pk_t);

void fhe_logicalOR(mpz_t*, mpz_t*, mpz_t*, fhe_pk_t);

void fhe_logicalXOR(mpz_t*, mpz_t*, mpz_t*, fhe_pk_t);

void fhe_logicalAND(mpz_t*, mpz_t*, mpz_t*, fhe_pk_t);



void fhe_wordAdder(mpz_t*, fhe_pk_t, mpz_t*, mpz_t*);

void fhe_wordSubtractor(mpz_t*, fhe_pk_t, mpz_t*, mpz_t*);

void fhe_wordMultiplier(mpz_t*, fhe_pk_t, mpz_t*, mpz_t*);

void fhe_1sComplement(mpz_t *, fhe_pk_t, mpz_t *);

void fhe_2sComplement(mpz_t *, fhe_pk_t, mpz_t *);

void fhe_isGreaterEqual(mpz_t, fhe_pk_t, mpz_t*, mpz_t*);

void fhe_isLessEqual(mpz_t, fhe_pk_t, mpz_t*, mpz_t*);

void fhe_isEqual(mpz_t, fhe_pk_t, mpz_t*, mpz_t*);

void fhe_isGreater(mpz_t, fhe_pk_t, mpz_t*, mpz_t*);
