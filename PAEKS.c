/*
An efficient public-key searchable encryption scheme secure against inside keyword guessing attacks
Qiong Huang, Hongbo Li
Information Sciences, Volumes 403–404, September 2017, Pages 1-14
https://www.sciencedirect.com/science/article/pii/S0020025516321090?via%3Dihub
*/

#include <gmp.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PAEKS_prime 984568127
#define PAEKS_seed_x 0
#define PAEKS_seed_y 1
#define PAEKS_seed_r 2
#define DEBUG 

// Define the parameters structure
typedef struct param{
    pairing_t pairing;
    mpz_t p;
    element_t g;
    element_t e;
    void (*H)(element_t, char*, int, element_t);
}PARAM;

void setup_H(element_t hash, char* input_str, int input_size, element_t g) {
    element_init_same_as(hash, g);
    element_from_hash(hash, input_str, input_size);
}

// Setup: Generate parameters
void PAEKS_Setup(PARAM* param, mpz_t lambda) {
    mpz_init(param->p);
    mpz_init_set_ui(param->p, PAEKS_prime);//gmp_printf("p: %Zd\n", param->p);
    pbc_param_t custom_param;
    pbc_param_init_a1_gen(custom_param, param->p);
    pairing_init_pbc_param(param->pairing, custom_param);    
    element_init_G1(param->g, param->pairing);
    element_random(param->g);//element_printf("g: %B\n", param->g);
    element_init_GT(param->e, param->pairing);
    element_pairing(param->e, param->g, param->g);//element_printf("e: %B\n", param->e);
    param->H = setup_H;
}

// Key Generation for Sender
void PAEKS_KeyGenS(PARAM param, element_t PkS, mpz_t SkS) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    srand(time(NULL));
    gmp_randseed_ui (state, rand()+PAEKS_seed_x);
    mpz_init(SkS);
	mpz_urandomm(SkS, state, param.p);
    //gmp_printf("SkS: %Zd\n", SkS);
    element_init_G1(PkS, param.pairing);
    element_pow_mpz(PkS, param.g, SkS);
    gmp_randclear(state);
}

// Key Generation for Receiver
void PAEKS_KeyGenR(PARAM param, element_t PkR, mpz_t SkR) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    srand(time(NULL));
    gmp_randseed_ui (state, rand()+PAEKS_seed_y);
    mpz_init(SkR);
	mpz_urandomm(SkR, state, param.p);
    //gmp_printf("SkR: %Zd\n", SkR);
    element_init_G1(PkR, param.pairing);
    element_pow_mpz(PkR, param.g, SkR);
    gmp_randclear(state);
}

// PEKS: Encrypt a keyword
void PAEKS_PEKS(PARAM param, element_t PkR, mpz_t SkS, char* keyword, element_t C1, element_t C2) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    srand(time(NULL));
    gmp_randseed_ui (state, rand()+PAEKS_seed_r);
    mpz_t r;
    mpz_init(r);
	mpz_urandomm(r, state, param.p);
    //gmp_printf("r: %Zd\n", r);
    
    element_t hash;
    param.H(hash, keyword, strlen(keyword), param.g);
    element_init_G1(C1, param.pairing);
    element_init_G1(C2, param.pairing);
    element_pow_mpz(C1, param.g, r);
    element_pow_mpz(hash, hash, SkS);
    element_mul(C1, hash, C1);
    element_pow_mpz(C2, PkR, r);
    
    element_clear(hash);
    mpz_clears(r, NULL);
    gmp_randclear(state);
}

// Trapdoor: Generate a trapdoor for a keyword
void PAEKS_Trapdoor(PARAM param, element_t PkS, mpz_t SkR, char* keyword, element_t Tw) {
    element_t hash;
    param.H(hash, keyword, strlen(keyword), param.g);//element_printf("hash: %B\n", hash);
    element_init_GT(Tw, param.pairing);
    element_pow_mpz(hash, hash, SkR);
    element_pairing(Tw, hash, PkS);//element_printf("Tw: %B\n", Tw);

    element_clear(hash);
}

// Test: Check if the trapdoor matches the ciphertext
int PAEKS_Test(PARAM param, element_t C1, element_t C2, element_t Tw, element_t PkS, element_t PkR) {
    element_t left, right;
    element_init_GT(left, param.pairing);
    element_init_GT(right, param.pairing);
    
    element_pairing(left, C2, param.g);
    element_mul(left, Tw, left);//element_printf("left: %B\n", left);
    element_pairing(right, C1, PkR);//element_printf("right: %B\n", right);
    
    if (element_cmp(left, right) == 0) {
        element_clear(left);
        element_clear(right);
        return 1;
    } else {
        element_clear(left);
        element_clear(right);
        return 0;
    }
}

void PAEKS_deletePARAM(PARAM* param){
    element_clear(param->g);
    pairing_clear(param->pairing);
    mpz_clears(param->p, NULL);
}

#if defined(DEBUG)
int main() {
    mpz_t lambda;
    mpz_init_set_ui(lambda, 256);
    PARAM *param = malloc(sizeof(PARAM));
    PAEKS_Setup(param, lambda);
    element_t PkS, PkR, C1, C2, Tw;
    mpz_t SkS, SkR;

    PAEKS_KeyGenS(*param, PkS, SkS);
    PAEKS_KeyGenR(*param, PkR, SkR);

    char* keyword = "test";

    PAEKS_PEKS(*param, PkR, SkS, keyword, C1, C2);
    PAEKS_Trapdoor(*param, PkS, SkR, keyword, Tw);
    
    int result = PAEKS_Test(*param, C1, C2, Tw, PkS, PkR);
    if (result == 1) {
        printf("Test passed: Keyword is matched.\n");
    } else {
        printf("Test failed: Keyword is not matched.\n");
    }

    PAEKS_deletePARAM(param);

    return 0;
}
#endif