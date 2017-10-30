/*
 * keys.c
 * 
 * Copyright 2017 chehw <chehw@chehw-HP8200>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "satoshi-protocol.h"
#include "shared_ptr.h"
#include "keys.h"
#include "utils.h"
#include "base58.h"
#include "sha512.h"
#include "ripemd160.h"

#include <openssl/rand.h>


#define TESTNET_PRIVKEY_VERSION htobe32(0x04358394)
#define TESTNET_PUBKEY_VERSION  htobe32(0x043587CF)
#define MAINNET_PRIVKEY_VERSION htobe32(0x0488ADE4)
#define MAINNET_PUBKEY_VERSION  htobe32(0x0488B21E)

static secp256k1_context * secp;
static inline secp256k1_context *  secp_init()
{
	secp256k1_context * ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	assert(NULL != ctx);
	return ctx;
}
ch_keys_t * ch_keys_init(ch_keys_t * keys, const unsigned char sec_key[])
{
	int rc;
	if(NULL == secp) 
	{
		secp = secp_init();
	}
	
	if(NULL == keys) 
	{
		keys = shared_ptr_malloc(sizeof(ch_keys_t));
		assert(NULL != keys);		
	}
	
	memset(keys, 0, sizeof(ch_keys_t));
	
	if(sec_key)
	{
		memcpy(keys->secret, sec_key, CH_KEY_SIZE);
	}else
	{
		RAND_bytes(keys->secret, CH_KEY_SIZE);		
	}
	rc = secp256k1_ec_pubkey_create(secp, keys->pubkey, keys->secret);
	assert(rc);
	
	keys->compressed = 1;
	return keys;
}

void ch_keys_cleanup(ch_keys_t * keys)
{
	if(keys)
	{
		memset(keys->secret, 0, CH_KEY_SIZE);
		shared_ptr_free(keys);
	}
}

ssize_t ch_keys_privkey_to_wif(ch_keys_t * keys, int testnet, char * to, size_t size)
{
#define EXT_DATA_LEN (1 + 32 + 1)
	ssize_t cb;
	unsigned char data[EXT_DATA_LEN + 32] = {0};
	data[0] = testnet?0xef:0x80;
	memcpy(&data[1], keys->secret, CH_KEY_SIZE);
	data[1 + 32] = keys->compressed?1:0;
	hash256(data, EXT_DATA_LEN, &data[EXT_DATA_LEN]);
	cb = base58_encode(data, EXT_DATA_LEN + 4, to, size);	
#undef EXT_DATA_LEN	
	return cb;
}

int ch_keys_privkey_import(ch_keys_t * keys, const char * wif)
{
#define EXT_DATA_LEN (1 + 32 + 1)
	ssize_t cb;
	uint256_t checksum;
	unsigned char data[EXT_DATA_LEN + 32] = {0};
	cb = base58_decode(wif, -1, data, sizeof(data));
	assert(cb == 38);
	
	hash256(data, EXT_DATA_LEN, checksum);
	assert(memcmp(checksum, &data[EXT_DATA_LEN], 4) == 0);
	
	int testnet = 0;
	if(data[0] == 0xef) testnet = 1;
	else if(data[0] == 0x80) testnet = 0;
	else 
	{
		printf("invalid network (%.2x)\n", data[0]);
		return -1;
	}
	
	if(ch_keys_init(keys, &data[1])) return 0;
	return -1;
#undef EXT_DATA_LEN		
}

ssize_t ch_keys_pubkey_to_addr(ch_keys_t * keys, int testnet, char * to, size_t size)
{
#define EXT_DATA_LEN (1 + 20)
	ssize_t cb;
	size_t cb_key;
	int rc;
	unsigned char pubkey[65] = {0};
	unsigned char data[EXT_DATA_LEN + 32] = {0};
	data[0] = testnet?111:0;
	
	cb_key = sizeof(pubkey);
	rc = secp256k1_ec_pubkey_serialize(secp, 
		pubkey, &cb_key, 
		keys->pubkey, 
		keys->compressed?SECP256K1_EC_COMPRESSED:SECP256K1_EC_UNCOMPRESSED); 
	assert(rc);
	
	hash160(pubkey, cb_key, &data[1]);	
	hash256(data, EXT_DATA_LEN, &data[EXT_DATA_LEN]);
	cb = base58_encode(data, EXT_DATA_LEN + 4, to, size);
#undef EXT_DATA_LEN	
	return cb;
}


//~ typedef struct ch_extkeys
//~ {
	//~ union
	//~ {
		//~ unsigned char hash[64];
		//~ struct 
		//~ {
			//~ unsigned char key[CH_KEY_SIZE];
			//~ unsigned char chain_code[CH_KEY_SIZE];
		//~ };
	//~ }hd;
	//~ int level;
	//~ uint32_t index;	
	//~ unsigned char parent_fingerprint[20];		
	//~ ch_keys_t keys;
//~ }ch_extkeys_t;

ch_extkeys_t * ch_extkeys_master_keygen(ch_extkeys_t * m, const unsigned char * seed, size_t seed_size, const unsigned char * seed_key, size_t seed_key_size)
{
	if(NULL == m)
	{
		m = shared_ptr_malloc(sizeof(ch_extkeys_t));
		assert(NULL != m);		
	}
	memset(m, 0, sizeof(ch_extkeys_t));	
	
	if(NULL == seed_key)
	{
		seed_key = (const unsigned char *)"Bitcoin seed";
		seed_key_size = sizeof("Bitcoin seed") - 1;
	}
	
	hmac_sha512_t hmac[1];
	hmac_sha512_init(hmac, seed_key, seed_key_size);
	hmac_sha512_update(hmac, seed, seed_size);
	hmac_sha512_final(hmac, m->hd.hash);
	
	m->level = 0;
	m->index = 0;	
	ch_keys_init(m->keys, m->hd.key);
	return m;
}

int ch_extkeys_derive(const ch_extkeys_t * parent, uint32_t index, ch_extkeys_t * child)
{
#define DATA_SIZE (33 + 4)
	
	int rc;
	unsigned char data[DATA_SIZE] = {0};
	int hard = (int)((index >> 31) & 0x01);
	child->index = -1;
	
	uint32_t be_index = htobe32(index);
	// calc parent finger print
	size_t cbkey = DATA_SIZE;
	rc = secp256k1_ec_pubkey_serialize(secp, data, &cbkey, parent->keys->pubkey, SECP256K1_EC_COMPRESSED);
	assert(rc);
	hash160(data, cbkey, child->parent_fingerprint);
	
	// Child key derivation (CKD) functions
	if(hard)
	{
		data[0] = 0;
		memcpy(&data[1], parent->hd.key, CH_KEY_SIZE);
	}	
	memcpy(&data[33], &be_index, 4);	
	hmac512(parent->hd.chain_code, CH_KEY_SIZE, data, DATA_SIZE, child->hd.hash);
	
	// verify seckey
	rc = secp256k1_ec_seckey_verify(secp, child->hd.key);
	if(rc <= 0) return -1;		
	rc = secp256k1_ec_privkey_tweak_add(secp, child->hd.key, parent->hd.key);
	assert(rc);
	
	// verify seckey
	rc = secp256k1_ec_seckey_verify(secp, child->hd.key);
	if(rc <= 0) return -1;	
	
	child->level = parent->level + 1;
	child->index = index;
	ch_keys_init(child->keys, child->hd.key);	
	return 0;
#undef DATA_SIZE
}

struct extkey_wif_data
{
	uint32_t version;
	uint8_t level;
	uint32_t finger_print;
	uint32_t index;
	uint8_t chain_code[32];
	uint8_t extkey[1 + 32];
	uint8_t checksum[4];
}__attribute__((packed));

int ch_extkeys_import(ch_extkeys_t * keys, const char * wif, size_t size)
{
#define DATA_SIZE (78)
	union
	{
		struct extkey_wif_data ext;
		unsigned char data[DATA_SIZE + 32];
	}extdata;
	
	if(size == -1) size = strlen(wif);
	ssize_t cb = base58_decode(wif, size, extdata.data, sizeof(extdata.data));
	printf("cb = %ld\n", cb);
	
	printf("version: 0x%.8x\n", extdata.ext.version);
	printf("level: %hhu\n", extdata.ext.level);
	printf("version: 0x%.8x\n", extdata.ext.finger_print);
	printf("index: 0x%.8x\n", extdata.ext.index);
	dump_line(stdout, "chain_code", extdata.ext.chain_code, 32);
	dump_line(stdout, "extkey", extdata.ext.extkey, 33);
	printf("checksum: "); dump(extdata.ext.checksum, 4);
	
	memcpy(keys->hd.key, extdata.ext.extkey + 1, 32);
	memcpy(keys->hd.chain_code, extdata.ext.chain_code, 32);
	keys->level = extdata.ext.level;
	memcpy(keys->parent_fingerprint, &extdata.ext.finger_print, 4);
	keys->index = be32toh(extdata.ext.index);
	ch_keys_init(keys->keys, keys->hd.key);
	
	return 0;
#undef DATA_SIZE
}

ssize_t ch_extkeys_privkey_to_wif(ch_extkeys_t * keys, int testnet, char * to, size_t size)
{
	ssize_t cb = 0;
#define DATA_SIZE (78)
	unsigned char data[DATA_SIZE + 32] = {0};
#define DEPTH_OFFSET 		(4)
#define FINGER_OFFSET 		(DEPTH_OFFSET + 1)
#define INDEX_OFFSET 		(FINGER_OFFSET + 4)
#define CHAIN_CODE_OFFSET 	(INDEX_OFFSET + 4)
#define EXTKEY_OFFSET 		(CHAIN_CODE_OFFSET + 32)

	if(testnet)
	{
		*(uint32_t *)&data[0] = TESTNET_PRIVKEY_VERSION;
	}else
	{
		*(uint32_t *)&data[0] = MAINNET_PRIVKEY_VERSION;
	}
	data[DEPTH_OFFSET] = keys->level;
	memcpy(&data[FINGER_OFFSET], keys->parent_fingerprint, 4);
	*(uint32_t *)&data[INDEX_OFFSET] = htobe32(keys->index);
	memcpy(&data[CHAIN_CODE_OFFSET], keys->hd.chain_code, CH_KEY_SIZE);
	data[EXTKEY_OFFSET] = 0;
	memcpy(&data[EXTKEY_OFFSET + 1], keys->hd.key, CH_KEY_SIZE);
	
	// checksum
	hash256(data, DATA_SIZE, &data[DATA_SIZE]);
	
	cb = base58_encode(data, DATA_SIZE + 4, to, size);	
	return cb;
#undef DEPTH_OFFSET 		//(4)
#undef FINGER_OFFSET 		//(DEPTH_OFFSET + 1)
#undef INDEX_OFFSET 		//(FINGER_OFFSET + 4)
#undef CHAIN_CODE_OFFSET 	//(INDEX_OFFSET + 4)
#undef EXTKEY_OFFSET 		//(CHAIN_CODE_OFFSET + 32)
#undef DATA_SIZE
}

void ch_extkeys_cleanup(ch_extkeys_t * keys)
{
	if(keys)
	{
		memset(keys, 0, sizeof(ch_extkeys_t));
		shared_ptr_free(keys);
	}
}
