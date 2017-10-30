#ifndef _KEYS_H_
#define _KEYS_H_

#include <stdio.h>
#include <stdint.h>
#include <secp256k1.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CH_KEY_SIZE 32
typedef struct ch_keys
{
	unsigned char secret[CH_KEY_SIZE];
	secp256k1_pubkey pubkey[1];
	int compressed;
}ch_keys_t;

ch_keys_t * ch_keys_init(ch_keys_t * keys, const unsigned char sec_key[32]);
void ch_keys_cleanup(ch_keys_t * keys);

ssize_t ch_keys_privkey_to_wif(ch_keys_t * keys, int testnet, char * to, size_t size);
ssize_t ch_keys_pubkey_to_addr(ch_keys_t * keys, int testnet, char * to, size_t size);
int ch_keys_privkey_import(ch_keys_t * keys, const char * wif);

typedef struct ch_extkeys
{
	union
	{
		unsigned char hash[64];
		struct 
		{
			unsigned char key[CH_KEY_SIZE];
			unsigned char chain_code[CH_KEY_SIZE];
		};
	}hd;
	int level;
	uint32_t index;	
	unsigned char parent_fingerprint[20];		
	ch_keys_t keys[1];
}ch_extkeys_t;

ch_extkeys_t * ch_extkeys_master_keygen(ch_extkeys_t * m, const unsigned char * seed, size_t seed_size, const unsigned char * seed_key, size_t seed_key_size);
int ch_extkeys_derive(const ch_extkeys_t * parent, uint32_t index, ch_extkeys_t * child);

int ch_extkeys_import(ch_extkeys_t * keys, const char * wif, size_t size);
ssize_t ch_extkeys_privkey_to_wif(ch_extkeys_t * keys, int testnet, char * to, size_t size);
void ch_extkeys_cleanup(ch_extkeys_t * keys);



#ifdef __cplusplus
}
#endif
#endif
