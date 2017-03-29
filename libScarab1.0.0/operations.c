#include "operations.h"

void memAlloc(mpz_t **c)
{
  *c = (mpz_t *) calloc(WORDLEN, sizeof(mpz_t));
}

void decimalToBinary(int a[], int n)
{
	int remainder, i = WORDLEN-1;

  n = WORDSIZE + n;
  while(n != 0)
	{
	   remainder = n%2;
     n = n/2;
     a[i--] = remainder;
  }
}

int binaryToDecimal(int a[])
{
	int i, n = 0 ;

	for(i=WORDLEN-1; i>=0; i--)
	{
		if(a[i] == 1)
			n += pow(2,WORDLEN-1-i);
	}
  if(a[0] == 1)
  {
    n -= WORDSIZE;
  }
	return n;
}

void binary_print(int a[])
{
	int i;

	for(i=0; i<WORDLEN; i++)
	{
		printf("%d",a[i]);
	}
}

void cipher_print(mpz_t *c)
{
	int i;

	for(i=0; i<WORDLEN; i++)
	{
		gmp_printf("%Zd\t", c);
	}
	printf("\n");
}

void fhe_wordEncrypt(mpz_t *c, fhe_pk_t pk, int a[])
{
	int i;

	for(i=0; i<WORDLEN; i++)
	{
		fhe_encrypt(c[i], pk, a[i]);
	}
}

void fhe_wordDecrypt(int a[], fhe_sk_t sk, mpz_t *c)
{
	int i;

	for(i=0; i<WORDLEN; i++)
	{
		a[i] = fhe_decrypt(c[i], sk);
	}
}

void fhe_NOT(mpz_t res, mpz_t a, fhe_pk_t pk)
{
  mpz_t b;

  mpz_init(b);

  fhe_encrypt(b, pk, 1);
	fhe_add(res, a, b, pk);

  mpz_clear(b);
}

void fhe_OR(mpz_t res, mpz_t a, mpz_t b, fhe_pk_t pk)
{
  mpz_t temp;
	mpz_init(temp);

	mpz_add(temp, a, b);
  mpz_addmul(temp, a, b);
	mpz_mod(res, temp, pk->p);
	fhe_recrypt(res, pk);

  mpz_clear(temp);
}

void fhe_XOR(mpz_t res, mpz_t a, mpz_t b, fhe_pk_t pk)
{
  fhe_add(res, a, b, pk);
}

void fhe_AND(mpz_t res, mpz_t a, mpz_t b, fhe_pk_t pk)
{
  fhe_mul(res, a, b, pk);
}

void fhe_logicalNOT(mpz_t *result, mpz_t *a, fhe_pk_t pk)
{
  int i;
  for(i=WORDLEN-1; i>=0; i--)
  {
    fhe_NOT(result[i], a[i], pk);
  }
}

void fhe_logicalOR(mpz_t *result, mpz_t *a, mpz_t *b, fhe_pk_t pk)
{
  int i;
  for(i=WORDLEN-1; i>=0; i--)
  {
    fhe_OR(result[i], a[i], b[i], pk);
  }
}

void fhe_logicalXOR(mpz_t *result, mpz_t *a, mpz_t *b, fhe_pk_t pk)
{
  int i;
  for(i=WORDLEN-1; i>=0; i--)
  {
    fhe_add(result[i], a[i], b[i], pk);
  }
}

void fhe_logicalAND(mpz_t *result, mpz_t *a, mpz_t *b, fhe_pk_t pk)
{
  int i;
  for(i=WORDLEN-1; i>=0; i--)
  {
    fhe_mul(result[i], a[i], b[i], pk);
  }
}

void fhe_wordAdder(mpz_t *c, fhe_pk_t pk, mpz_t *c0, mpz_t *c1)
{
	int i;
	mpz_t in, out;

	mpz_init(in);
  mpz_init(out);

	for(i=WORDLEN-1; i>=0; i--)
	{
		if(i==WORDLEN-1)
			fhe_halfadd(c[i], out, c0[i], c1[i], pk);
		else
			fhe_fulladd(c[i], out, c0[i], c1[i], in, pk);
    fhe_recrypt(c[i], pk);
    fhe_recrypt(out, pk);
		mpz_set(in, out);
	}

	mpz_clear(in);
  mpz_clear(out);
}

void fhe_wordSubtractor(mpz_t *c, fhe_pk_t pk, mpz_t *c0, mpz_t *c1)
{
	int i;
	mpz_t in, out, *c2;

	mpz_init(in);
  mpz_init(out);
  memAlloc(&c2);

  fhe_encrypt(in, pk, 1);
  for(i=WORDLEN-1; i>=0; i--)
	{
    fhe_NOT(c2[i], c1[i], pk);
	}
	for(i=WORDLEN-1; i>=0; i--)
	{
    fhe_fulladd(c[i], out, c2[i], c0[i], in, pk);
    fhe_recrypt(c[i], pk);
    fhe_recrypt(out, pk);
		mpz_set(in, out);
	}

	mpz_clear(in);
  mpz_clear(out);
  free(c2);
}

void fhe_wordMultiplier(mpz_t *c, fhe_pk_t pk, mpz_t *c0, mpz_t *c1)
{
  int i, j, k;
  mpz_t in, out, *multemp, *addtemp;

  mpz_init(in);
  mpz_init(out);
  memAlloc(&multemp);
  memAlloc(&addtemp);

  for(i=0; i<WORDLEN*2; i++)
	{
		fhe_encrypt(c[i], pk, 0);
	}

  for(i=WORDLEN-1; i>=0; i--)
  {
    for(j=i+1,k=0; j<=i+WORDLEN; j++,k++)
    {
      mpz_set(addtemp[k],c[j]);
    }
    for(j=WORDLEN-1; j>=0; j--)
    {
      fhe_mul(multemp[j], c0[j], c1[i], pk);
      fhe_recrypt(multemp[i], pk);
    }
    for(j=WORDLEN-1, k=i+WORDLEN; j>=0; j--,k--)
  	{
  		if(j==WORDLEN-1)
  			fhe_halfadd(c[k], out, addtemp[j], multemp[j], pk);
  		else
  			fhe_fulladd(c[k], out, addtemp[j], multemp[j], in, pk);
      fhe_recrypt(c[k], pk);
      fhe_recrypt(out, pk);
  		mpz_set(in, out);
  	}
    mpz_set(c[i],out);
  }

  mpz_clear(in);
  mpz_clear(out);
  free(multemp);
  free(addtemp);
}

void fhe_1sComplement(mpz_t *c1, fhe_pk_t pk, mpz_t *c0)
{
  int i;

  for(i=WORDLEN-1; i>=0; i--)
	{
    fhe_NOT(c1[i], c0[i], pk);
	}
}

void fhe_2sComplement(mpz_t *c1, fhe_pk_t pk, mpz_t *c0)
{
  int i;
	mpz_t in, out, *c2;

  mpz_init(in);
  mpz_init(out);
  memAlloc(&c2);

  fhe_encrypt(in, pk, 1);
  for(i=WORDLEN-1; i>=0; i--)
	{
    fhe_NOT(c2[i], c0[i], pk);
	}
  for(i=WORDLEN-1; i>=0; i--)
  {
    fhe_halfadd(c1[i], out, c2[i], in, pk);
    fhe_recrypt(c1[i], pk);
    fhe_recrypt(out, pk);
    mpz_set(in, out);
  }

  mpz_clear(in);
  mpz_clear(out);
  free(c2);
}

void fhe_isGreaterEqual(mpz_t res, fhe_pk_t pk, mpz_t *c0, mpz_t *c1)
{
  mpz_t *c2;

  memAlloc(&c2);

  fhe_wordSubtractor(c2, pk, c0, c1);
  fhe_NOT(res, c2[0], pk);

  free(c2);
}

void fhe_isLessEqual(mpz_t res, fhe_pk_t pk, mpz_t *c0, mpz_t *c1)
{
  mpz_t *c2;

  memAlloc(&c2);

  fhe_wordSubtractor(c2, pk, c0, c1);
  mpz_set(res, c2[0]);

  free(c2);
}

void fhe_isEqual(mpz_t res, fhe_pk_t pk, mpz_t *c0, mpz_t *c1)
{
  int i;
  mpz_t *c2, *c3;

  memAlloc(&c2);
  memAlloc(&c3);

  fhe_wordSubtractor(c2, pk, c0, c1);
  for(i=WORDLEN-1; i>=0; i--)
	{
    fhe_NOT(c3[i], c2[i], pk);
	}
  mpz_set(res, c3[0]);
  for(i=1; i<WORDLEN; i++)
	{
    fhe_mul(res, res, c3[i], pk);
	}

  free(c2);
  free(c3);
}

//void fhe_isGreater(mpz_t, fhe_pk_t, mpz_t*, mpz_t*)
//{

//}
