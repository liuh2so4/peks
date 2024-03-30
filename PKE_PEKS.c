/*
On the Integration of Public Key Data Encryption and Public Key Encryption with Keyword Search
Joonsang Baek, Reihaneh Safavi-Naini & Willy Susilo
ISC 2006: Information Security pp 217–232
https://link.springer.com/chapter/10.1007/11836810_16
*/

#include <gmp.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PKE_PEKS_prime 4294967857
#define PKE_PEKS_seed_x 0
#define PKE_PEKS_seed_r 1
#define DEBUG 

typedef struct Parameter{
    pairing_t pairing;
    mpz_t q;
    element_t g;
    void (*H1)(unsigned char*, element_t, size_t);
    void (*H2)(element_t, char*, int, element_t);
    void (*H3)(unsigned char*, element_t, size_t);
    void (*H4)(element_t, unsigned char*, element_t, unsigned char*, unsigned char*, size_t, unsigned char**);
} PARAMETER;

void KeyGen_H1_H3(unsigned char* hash, element_t element, size_t output_size) {
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    mpz_t x;
    mpz_init(x);
    element_to_mpz(x, element);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, mpz_get_str(NULL, 10, x), strlen(mpz_get_str(NULL, 10, x)));
    SHA256_Final(sha256_hash, &sha256);
    memcpy(hash, sha256_hash, output_size);
    mpz_clear(x);
}

void KeyGen_H2(element_t hash, char* input_str, int input_size, element_t g) {
    element_init_same_as(hash, g);
    element_from_hash(hash, input_str, input_size);
}

void KeyGen_H4(element_t kappa, unsigned char* m, element_t c1, unsigned char* c2, unsigned char* tau, size_t l4, unsigned char **output) {
    // Convert the element to a byte array
    size_t kappa_len = element_length_in_bytes(kappa);
    unsigned char *kappa_bytes = malloc(kappa_len);
    element_to_bytes(kappa_bytes, kappa);
    size_t c1_len = element_length_in_bytes(c1);
    unsigned char *c1_bytes = malloc(c1_len);
    element_to_bytes(c1_bytes, c1);

    size_t totalLength = strlen((char*)kappa_bytes) + strlen((char*)m) + strlen((char*)c1_bytes) + strlen((char*)c2) + strlen((char*)tau) + 1;
    unsigned char* input_str = (unsigned char*)malloc(totalLength);
    sprintf((char*)input_str, "%s%s%s%s%s", kappa_bytes, m, c1_bytes, c2, tau);

    // Use SHA-256 to hash the input string
    unsigned char hash_result[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input_str, strlen(input_str));
    SHA256_Final(hash_result, &sha256);
    
    // Truncate or pad the result to the desired length l4
    *output = (unsigned char*)malloc(l4);
    memcpy(*output, hash_result, l4);
    // for (size_t i = 0; i < l4; ++i) {
    //     printf("%02x", (*output)[i]);
    // }
    // printf("\n");
    free(c1_bytes);
    free(input_str);
}

void print_H1_H3_result(unsigned char *hash_result, size_t length) {
    printf("Hash Result: ");
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", hash_result[i]);
    }
    printf("\n");
}

void charToBinary(const char* input, size_t inputLength, char* output) {
    for (size_t i = 0; i < inputLength; ++i) {
        char currentChar = input[i];
        for (int j = 7; j >= 0; --j) {
            // Extract each bit of the character
            output[i * 8 + (7 - j)] = ((currentChar >> j) & 1) + '0';
        }
    }
}

void binaryToChar(const char* binaryInput, size_t binaryLength, char* charOutput) {
    if (binaryLength % 8 != 0) {
        fprintf(stderr, "Binary length must be a multiple of 8\n");
        exit(1);  // Exit with an error code
    }
    size_t charLength = binaryLength / 8;
    for (size_t i = 0; i < charLength; ++i) {
        char currentChar = 0;
        for (int j = 7; j >= 0; --j) {
            currentChar |= (binaryInput[i * 8 + (7 - j)] - '0') << j;
        }
        charOutput[i] = currentChar;
    }
    charOutput[charLength] = '\0';
}

void PKE_Setup(PARAMETER* params) {
    mpz_init(params->q);
    mpz_init_set_ui(params->q, PKE_PEKS_prime);//gmp_printf("q: %Zd\n", params->q);
    pbc_param_t custom_param;
    pbc_param_init_a1_gen(custom_param, params->q);
    pairing_init_pbc_param(params->pairing, custom_param);
    element_init_G1(params->g, params->pairing);
    element_random(params->g);//element_printf("params->g: %B\n", params->g);
    params->H1 = KeyGen_H1_H3;
    params->H2 = KeyGen_H2;
    params->H3 = KeyGen_H1_H3;
    params->H4 = KeyGen_H4;
}

void PKE_KeyGen(PARAMETER params, mpz_t sk, element_t pk) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    srand(time(NULL));
    gmp_randseed_ui(state, rand()+PKE_PEKS_seed_x);
    mpz_init(sk);
	mpz_urandomm(sk, state, params.q);//gmp_printf("sk: %Zd\n", sk);
    element_init_G1(pk, params.pairing);
    element_pow_mpz(pk, params.g, sk);//element_printf("pk: %B\n", pk);
    gmp_randclear(state);
}

void PKE_Encrypt(PARAMETER params, element_t pk, unsigned char* w, unsigned char* plaintext, element_t c1, unsigned char** c2, unsigned char** tau, unsigned char** sigma) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    srand(time(NULL));
    gmp_randseed_ui(state, rand()+PKE_PEKS_seed_r);
    mpz_t r;
    mpz_init(r);
	mpz_urandomm(r, state, params.q);
    element_init_G1(c1, params.pairing);
    element_pow_mpz(c1, params.g, r);//element_printf("c1: %B\n", c1);
    element_t kappa, h, mu;
    unsigned char* K = (unsigned char*)malloc((256) * sizeof(unsigned char));
    element_init_G1(kappa, params.pairing);
    element_pow_mpz(kappa, pk, r);
    params.H1(K, kappa, SHA256_DIGEST_LENGTH);
    // c2 = K xor m
    size_t mLength = strlen(plaintext);
    size_t binaryLength = mLength * 8;
    char* binaryMessage = (unsigned char*) malloc(binaryLength + 1);;
    charToBinary(plaintext, mLength, binaryMessage);
    *c2 = (unsigned char*) malloc(binaryLength + 1);
    if (*c2 != NULL) {//printf("binaryLength: %zu\n", binaryLength);
        for (size_t i = 0; i < binaryLength; ++i) {
            (*c2)[i] = K[i % SHA256_DIGEST_LENGTH] ^ binaryMessage[i];
            // printf("%02x", (*c2)[i]);
        }
        (*c2)[binaryLength] = '\0';
        // printf("\n");
    } else {
        printf("Memory allocation failed\n");
    }
    params.H2(h, w, strlen(w), params.g);
    element_init_GT(mu, params.pairing);
    element_pairing(mu, h, pk);
    element_pow_mpz(mu, mu, r);//element_printf("mu: %B\n", mu);
    *tau = (unsigned char*)malloc((SHA256_DIGEST_LENGTH) * sizeof(unsigned char));
    params.H3(*tau, mu, SHA256_DIGEST_LENGTH);//print_H1_H3_result(tau, 256/8);
    params.H4(kappa, plaintext, c1, *c2, *tau, SHA256_DIGEST_LENGTH, sigma);
    gmp_randclear(state);
    mpz_clear(r);
    element_clear(kappa);
    element_clear(h);
    element_clear(mu);
    free(K);
    free(binaryMessage);
}

void PKE_Trapdoor(PARAMETER params, mpz_t sk, char* w, element_t tw){
    params.H2(tw, w, strlen(w), params.g);
    element_pow_mpz(tw, tw, sk);
}

int PKE_Test(PARAMETER params, element_t c1, unsigned char* tau, element_t tw) {
    element_t e;
    unsigned char* hash = (unsigned char*)malloc((SHA256_DIGEST_LENGTH) * sizeof(unsigned char));
    element_init_GT(e, params.pairing);
    element_pairing(e, tw, c1);//element_printf("test e: %B\n", e);
    params.H3(hash, e, SHA256_DIGEST_LENGTH);//print_H1_H3_result(hash, 256/8);
    element_clear(e);
    if (memcmp(hash, tau, SHA256_DIGEST_LENGTH) == 0){
        return 1; // "yes"
    } else {
        return 0; // "no"
    }
}

char* PKE_Decrypt(PARAMETER params, mpz_t sk, element_t c1, unsigned char* c2, unsigned char* tau, unsigned char* sigma) {
    element_t kappa;
    unsigned char* K = (unsigned char*)malloc((SHA256_DIGEST_LENGTH) * sizeof(unsigned char));
    element_init_G1(kappa, params.pairing);
    element_pow_mpz(kappa, c1, sk);
    params.H1(K, kappa, SHA256_DIGEST_LENGTH);
    // m = K xor c2
    size_t binaryLength = strlen(c2);//printf("binaryLength: %zu\n", binaryLength);
    char* binaryMessage = (unsigned char*) malloc(binaryLength + 1);
    for (int i = 0; i < binaryLength; ++i) {
        binaryMessage[i] = K[i % SHA256_DIGEST_LENGTH] ^ c2[i];
        // printf("%02x", binaryMessage[i]);
    }
    binaryMessage[binaryLength] = '\0';
    // printf("\n");
    unsigned char* m = (unsigned char*) malloc(binaryLength / 8);
    binaryToChar(binaryMessage, binaryLength, m);
    //printf("Converted Char: %s\n", m);
    unsigned char* hash4;
    params.H4(kappa, m, c1, c2, tau, SHA256_DIGEST_LENGTH, &hash4);
    if(memcmp(hash4, sigma, SHA256_DIGEST_LENGTH) == 0){
        element_clear(kappa);
        free(hash4);
        free(K);
        free(binaryMessage);
        return m;
    }
    else{
        element_clear(kappa);
        free(hash4);
        free(K);
        free(binaryMessage);
        return "reject";
    }
}

void PKE_deletePARAMETER(PARAMETER* params){
    element_clear(params->g);
    pairing_clear(params->pairing);
    mpz_clears(params->q, NULL);
}

#if defined(DEBUG)
int main() {
    PARAMETER params;
    element_t pk;
    mpz_t sk;
    element_t c1, tw;
    unsigned char* c2 = NULL;
    unsigned char* tau = NULL;
    unsigned char* sigma = NULL;
    char* keyword = "example";
    char* plaintext = "Hello, world!";
    char* message;

    PKE_Setup(&params);
    PKE_KeyGen(params, sk, pk);
    PKE_Encrypt(params, pk, keyword, plaintext, c1, &c2, &tau, &sigma);
    PKE_Trapdoor(params, sk, keyword, tw);
    int test_result = PKE_Test(params, c1, tau, tw);
    if (test_result == 1) {
        printf("Test passed: Keyword is matched.\n");
        message = strdup(PKE_Decrypt(params, sk, c1, c2, tau, sigma));
        printf("Decrypted Message: %s\n", message);
    } else {
        printf("Test failed: Keyword is not matched.\n");
    }

    mpz_clear(sk);
    element_clear(pk);
    element_clear(c1);
    element_clear(tw);

    PKE_deletePARAMETER(&params);

    return 0;
}
#endif