/*
Public Key Encryption with Keyword Search Revisited
Joonsang Baek1, Reihaneh Safavi-Naini2, and Willy Susilo3
ICCSA 2008: Computational Science and Its Applications – ICCSA 2008 pp 1249–1259
https://link.springer.com/chapter/10.1007/978-3-540-69839-5_96
*/

#include <gmp.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SCF_PEKS_prime 4294967857
#define SCF_PEKS_seed_x 0
#define SCF_PEKS_seed_y 1
#define SCF_PEKS_seed_r 2
#define DEBUG 

// Define the parameters structure
typedef struct CommonParameter{
    pairing_t pairing;
    // element_t g1;
    element_t e;
    element_t P;
    mpz_t q;
    size_t k;
    void (*H1)(element_t, char*, int, element_t);
    void (*H2)(unsigned char**, element_t, size_t);
} COMMONPARAMETER;

typedef struct PublickeyServer{
    element_t Q;
    element_t X;
}PUBLICKEYSERVER;

typedef struct Secret{
    element_t U;
    unsigned char* V;
}SECRET;

void Setup_H1(element_t hash, char* input_str, int input_size, element_t g) {
    element_init_same_as(hash, g);
    element_from_hash(hash, input_str, input_size);
}

void Setup_H2(unsigned char** hash, element_t element, size_t output_size) {
    *hash = (unsigned char*)malloc((output_size) * sizeof(unsigned char));
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    mpz_t x;
    mpz_init(x);
    element_to_mpz(x, element);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, mpz_get_str(NULL, 10, x), strlen(mpz_get_str(NULL, 10, x)));
    SHA256_Final(sha256_hash, &sha256);
    memcpy(*hash, sha256_hash, output_size);
    mpz_clear(x);
}

void print_H2_result(unsigned char *hash_result, size_t length) {
    printf("Hash Result: ");
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", hash_result[i]);
    }
    printf("\n");
}

// Setup: Generate parameters
void SCF_Setup(COMMONPARAMETER* cp, size_t k) {
    mpz_init(cp->q);
    mpz_init_set_ui(cp->q, SCF_PEKS_prime);//gmp_printf("q: %Zd\n", cp->q);
    pbc_param_t custom_param;
    pbc_param_init_a1_gen(custom_param, cp->q);
    pairing_init_pbc_param(cp->pairing, custom_param);
    // element_init_G1(cp->g1, cp->pairing);
    element_init_G1(cp->P, cp->pairing);
    element_random(cp->P);//element_printf("P: %B\n", cp->P);
    element_init_GT(cp->e, cp->pairing);
    element_pairing(cp->e, cp->P, cp->P);//element_printf("e: %B\n", cp->e);
    cp->H1 = Setup_H1;
    cp->k = k;
    cp->H2 = Setup_H2;
}

// Key Generation for Server
void SCF_KeyGenServer(COMMONPARAMETER cp, mpz_t skS, PUBLICKEYSERVER* pkS) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    srand(time(NULL));
    gmp_randseed_ui(state, rand()+SCF_PEKS_seed_x);
    mpz_init(skS);
	mpz_urandomm(skS, state, cp.q);
    element_init_G1(pkS->X, cp.pairing);
    element_init_G1(pkS->Q, cp.pairing);
    element_pow_mpz(pkS->X, cp.P, skS);//element_printf("pkS->X: %B\n", pkS->X);
    element_random(pkS->Q);//element_printf("pkS->Q: %B\n", pkS->Q);
}

// Key Generation for Receiver
void SCF_KeyGenReceiver(COMMONPARAMETER cp, mpz_t skR, element_t pkR) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    srand(time(NULL));
    gmp_randseed_ui (state, rand()+SCF_PEKS_seed_y);
    mpz_init(skR);
	mpz_urandomm(skR, state, cp.q);
    element_init_G1(pkR, cp.pairing);
    element_pow_mpz(pkR, cp.P, skR);//element_printf("pkR: %B\n", pkR);
    gmp_randclear(state);
}

// SCF-PEKS: Encrypt a keyword
void SCF_PEKS(COMMONPARAMETER cp, PUBLICKEYSERVER pkS, element_t pkR, char* keyword, SECRET* S) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    srand(time(NULL));
    gmp_randseed_ui(state, rand()+SCF_PEKS_seed_r);
    mpz_t r;
    mpz_init(r);
	mpz_urandomm(r, state, cp.q);
    
    element_init_G1(S->U, cp.pairing);
    element_pow_mpz(S->U, cp.P, r);//element_printf("S->U: %B\n", S->U);
    
    element_t hash;
    cp.H1(hash, keyword, strlen(keyword), cp.P);
    element_t e_back;
    element_init_GT(e_back, cp.pairing);
    element_pairing(e_back, hash, pkR);
    element_t e_front;
    element_init_GT(e_front, cp.pairing);
    element_pairing(e_front, pkS.Q, pkS.X);
    element_t kappa;
    element_init_GT(kappa, cp.pairing);
    element_mul(kappa, e_front, e_back);
    element_pow_mpz(kappa, kappa, r);//element_printf("kappa: %B\n", kappa);
    cp.H2(&S->V, kappa, cp.k);//print_H2_result(S->V, (cp.k / 8));
    element_clear(hash);
    element_clear(e_back);
    element_clear(e_front);
    element_clear(kappa);
    mpz_clears(r, NULL);
    gmp_randclear(state);
}

// Trapdoor: Generate a trapdoor for a keyword
void SCF_Trapdoor(COMMONPARAMETER cp, mpz_t skR, char* keyword, element_t Tw) {
    cp.H1(Tw, keyword, strlen(keyword), cp.P);
    element_mul_mpz(Tw, Tw, skR);
}

// Test: Check if the trapdoor matches the ciphertext
int SCF_Test(COMMONPARAMETER cp, SECRET S, element_t Tw, mpz_t skS, PUBLICKEYSERVER pkS, char* keyword) {
    unsigned char* hash;
    element_t e, tmp;
    element_init_G1(tmp, cp.pairing);
    element_init_GT(e, cp.pairing);
    element_mul_mpz(tmp, pkS.Q, skS);
    element_add(tmp, tmp, Tw);
    element_pairing(e, tmp, S.U);//element_printf("e: %B\n", e);
    cp.H2(&hash, e, cp.k);//print_H2_result(hash, (cp.k / 8));
    
    if (memcmp(hash, S.V, (cp.k / 8)) == 0) {
        element_clear(e);
        free(hash);
        element_clear(tmp);
        return 1;
    } else {
        element_clear(e);
        free(hash);
        element_clear(tmp);
        return 0;
    }
}

void SCF_deleteCommonParameter(COMMONPARAMETER* cp){
    element_clear(cp->P);
    element_clear(cp->e);
    pairing_clear(cp->pairing);
    mpz_clears(cp->q, NULL);
}

#if defined(DEBUG)
int main() {
    COMMONPARAMETER cp;
    size_t k=256;
    PUBLICKEYSERVER pkS;
    element_t pkR;
    mpz_t skS, skR;
    SECRET S;
    element_t Tw;

    SCF_Setup(&cp, k);
    SCF_KeyGenServer(cp, skS, &pkS);
    SCF_KeyGenReceiver(cp, skR, pkR);

    char* keyword = "test";
    SCF_PEKS(cp, pkS, pkR, keyword, &S);
    SCF_Trapdoor(cp, skR, keyword, Tw);

    int result = SCF_Test(cp, S, Tw, skS, pkS, keyword);
    if (result == 1) {
        printf("Test passed: Keyword is matched.\n");
    } else {
        printf("Test failed: Keyword is not matched.\n");
    }

    SCF_deleteCommonParameter(&cp);

    return 0;
}
#endif