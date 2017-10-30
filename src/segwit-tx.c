/*
 * segwit-tx.c
 * 
 * Copyright 2017 chehw <htc.chehw@gmail.com>
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
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "app.h"

#include "utils.h"
#include "satoshi-protocol.h"
#include "satoshi-network.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include <secp256k1.h>

#include <sys/epoll.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

#include "base58.h"

#include <secp256k1.h>
#include <json-c/json.h>

#include "keys.h"
#include "shared_ptr.h"
#include "bitcoin-consensus.h"
#include "satoshi-script.h"

#include "segwit-tx.h"

#ifndef COIN
#define COIN (100000000LL)
#endif

static ssize_t satoshi_addr_to_script(const char * addr, int addr_len, 
	unsigned char script[], 
	size_t script_size)
{
	size_t cb;
	unsigned char ext_data[100];
	size_t cb_data;
	cb_data = base58_decode(addr, addr_len, ext_data, sizeof(ext_data));
	assert(cb_data > 0 && cb_data != -1);
	
	int type = 0;
	if(ext_data[0] == 0) type = 1; // p2pubkey
	else if(ext_data[0] == 5) type = 5; // p2sh
	else 
	{
		debug_printf("unsupport addr type (%d)\n", (int)ext_data[0]);
		return -1;
	}
	
	unsigned char *p = script;
	if(type == 1) *p++ = OP_DUP;
	
	*p++ = OP_HASH160;
	*p++ = (unsigned char)20;	// hash160 size
	memcpy(p, &ext_data[1], 20); p += 20;
	
	if(type == 1) 
	{
		*p++ = OP_EQUALVERIFY;
		*p++ = OP_CHECKSIG;
	}else if(type == 5)
	{
		*p++ = OP_EQUAL;
	}
	cb = (size_t)(p - script);
	
	return cb;
}

void segwit_rawtx_dump(segwit_rawtx_t * rawtx)
{
	int64_t in_value = 0;
	int64_t out_value = 0;
	int i;
	int in_count = rawtx->in_count;
	int out_count = rawtx->out_count;
	
	printf("dump txin...\n");
	printf("version: %d (%.8x)\n", rawtx->version, (uint32_t)rawtx->version);
	dump_line(stdout, "prev_outputs_hash", rawtx->prev_outputs_hash, 32);
	dump_line(stdout, "sequence_hash", rawtx->sequence_hash, 32);
	
	for(i = 0; i < in_count; ++i)
	{
		printf("raw_txin[%d]: ", i); 
		dump(&rawtx->raw_txin[i].input, sizeof(rawtx->raw_txin[i].input));
		printf("amount: %.8f\n", (double)rawtx->raw_txin[i].value / (double)COIN );
		printf("pk_script: "); 
		dump(rawtx->raw_txin[i].pk_script->vch, varstr_size(rawtx->raw_txin[i].pk_script));
		in_value += rawtx->raw_txin[i].value;
	}
	printf("in_count: %d, total_values: %ld\n", in_count, (long)in_value);
		
	for(i = 0; i < out_count; ++i)
	{
		printf("txout[%d]; ", i);
		printf("amount: %.8f\n", (double)rawtx->txouts[i].value / (double)COIN );
		out_value += rawtx->txouts[i].value;
		printf("pk_script: "); 
		dump(rawtx->txouts[i].pk_script->vch, varstr_size(rawtx->txouts[i].pk_script));
	}
	
	printf("out_count: %d, total_values: %ld\n", out_count, (long)out_value);
	printf("fees: %ld (%.8f)\n", (long)(in_value - out_value),
		(double)(in_value - out_value) / (double)COIN);
	
	dump_line(stdout, "outputs_hash", rawtx->outputs_hash, 32);
	printf("lock_time: %u (0x%.8x)\n", rawtx->lock_time, rawtx->lock_time);
	printf("hash_type: %u (0x%.8x)\n", rawtx->hash_type, rawtx->hash_type);
	
}

segwit_rawtx_t * segwit_rawtx_init(segwit_rawtx_t * rawtx, 
	int32_t version,
	json_object * j_inputs,
	json_object * j_outputs,
	uint32_t lock_time,
	uint32_t hash_type,
	json_object * j_unspent_list,
	json_object * j_privkeys
	)
{
	int i;
	int rc;
	int in_count = 0;
	int out_count = 0;
	unsigned char script[4096] = "";
	ssize_t cb_script = 0;
		
	segwit_raw_txin_t * raw_txin = NULL;
	satoshi_txout_t * txouts = NULL;
	assert(NULL != j_inputs && NULL != j_outputs);
	if(NULL == rawtx)
	{
		rawtx = calloc(1, sizeof(segwit_rawtx_t));
		assert(NULL != rawtx);
	}
	
	in_count = json_object_array_length(j_inputs);
	out_count = json_object_array_length(j_outputs);
	assert(in_count > 0 && out_count > 0);
	
	raw_txin = calloc(in_count, sizeof(segwit_raw_txin_t));	
	assert(NULL != raw_txin);
	
	txouts = calloc(out_count, sizeof(satoshi_txout_t));
	assert(NULL != txouts);
	
	printf("in_count = %d\n", in_count);
	for(i = 0; i < in_count; ++i)
	{		
		json_object * jitem = json_object_array_get_idx(j_inputs, i);
		assert(NULL != jitem);
		
		json_object * jtxid = NULL;
		json_object * jvout = NULL;
		json_object * jsequence = NULL;
		json_object * jamount = NULL;
		json_object * jscript = NULL;
		int cb_txid;		
		
		rc = json_object_object_get_ex(jitem, "txid", &jtxid);
		assert(rc);
		rc = json_object_object_get_ex(jitem, "vout", &jvout);
		assert(rc);
		rc = json_object_object_get_ex(jitem, "sequence", &jsequence);
		assert(rc);
		
		cb_txid = json_object_get_string_len(jtxid);
		assert(cb_txid == 64);
		cb_txid = hex2bin(
			json_object_get_string(jtxid),
			cb_txid,
			raw_txin[i].outpoint.hash);
		reverse_bytes(raw_txin[i].outpoint.hash, 32); // convert litten endian to big endian
		raw_txin[i].outpoint.index = json_object_get_int(jvout);
		raw_txin[i].sequence = (uint32_t)json_object_get_int64(jsequence);
		
		rc = json_object_object_get_ex(jitem, "amount", &jamount);
		if(rc)
		{
			raw_txin[i].value = (int64_t)(json_object_get_double(jamount) * COIN);
		}
		
		memset(script, 0, sizeof(script));
		cb_script = 0;
		rc = json_object_object_get_ex(jitem, "scriptPubKey", &jscript);
		if(rc)
		{
			cb_script = hex2bin(json_object_get_string(jscript),
				json_object_get_string_len(jscript),
				script);
			raw_txin[i].pk_script = varstr_set(NULL, script, cb_script);
		}
		
	}
	
	printf("out_count = %d\n", out_count);
	for(i = 0; i < out_count; ++i)
	{
		json_object * jitem = json_object_array_get_idx(j_outputs, i);
		assert(NULL != jitem);
		json_object * jamount = NULL;
		json_object * jaddr = NULL;
		json_object * jscript = NULL;
		
		
		rc = json_object_object_get_ex(jitem, "amount", &jamount);		
		assert(rc);
		rc = json_object_object_get_ex(jitem, "address", &jaddr);
		if(!rc)
		{
			rc = json_object_object_get_ex(jitem, "script", &jscript);
		}
		assert(rc);
		
		txouts[i].value = (int64_t)(json_object_get_double(jamount) * 100000000LL);
		printf("value[%d] = %ld\n", i, txouts[i].value);
		
		if(jaddr)
		{
			
			cb_script = satoshi_addr_to_script(
				json_object_get_string(jaddr), 
				json_object_get_string_len(jaddr),
				script, 
				sizeof(script));
			printf("script from addr: "); dump(script, cb_script);
		}else if(jscript)
		{
			cb_script = hex2bin(
				json_object_get_string(jscript), 
				json_object_get_string_len(jscript),
				script);
			printf("script: "); dump(script, cb_script);
		}
		if(cb_script) txouts[i].pk_script = varstr_set(NULL, script, cb_script);
		
		
	}
	
	rawtx->in_count = in_count;
	rawtx->out_count = out_count;
	rawtx->raw_txin = raw_txin;
	rawtx->txouts = txouts;
	
	rawtx->version = version;
	rawtx->lock_time = lock_time;
	rawtx->hash_type = hash_type;
	
// calc hashes
	
	size_t cb_prev_outs = in_count * sizeof(satoshi_outpoint_t);
	satoshi_outpoint_t * prev_outs = malloc(cb_prev_outs);
	assert(NULL != prev_outs);
	
	size_t cb_sequences = in_count * sizeof(uint32_t);
	uint32_t * sequences = malloc(cb_sequences);
	assert(NULL != sequences);
	
	for(i = 0; i < in_count; ++i)
	{
		memcpy(&prev_outs[i], &rawtx->raw_txin[i].outpoint, sizeof(satoshi_outpoint_t));	
		sequences[i] = rawtx->raw_txin[i].sequence;
	}
	
	// calc prevouts hash
	hash256(prev_outs, cb_prev_outs, rawtx->prev_outputs_hash);
	free(prev_outs);
	
	// calc sequence hash
	hash256(sequences, cb_sequences, rawtx->sequence_hash);
	free(sequences);
	
	size_t cb_outputs = 0;	
	unsigned char * outputs = NULL;
	unsigned char * p;
	for(i = 0; i < out_count; ++i)
	{
		cb_outputs += sizeof(int64_t) + varstr_size(txouts[i].pk_script);
	}
	assert(cb_outputs > 0);
	outputs = malloc(cb_outputs);
	assert(NULL != outputs);
	
	p = outputs;
	for(i = 0; i < out_count; ++i)
	{
		*(int64_t *)p = txouts[i].value; p += sizeof(int64_t);
		memcpy(p, txouts[i].pk_script->vch, varstr_size(txouts[i].pk_script));
		p += varstr_size(txouts[i].pk_script);
	}
	assert((p - outputs) == cb_outputs);
	hash256(outputs, cb_outputs, rawtx->outputs_hash);
	
	return rawtx;
}

int segwit_rawtx_generate_preimage(segwit_rawtx_t * rawtx, int input_index, unsigned char ** p_image, size_t * p_image_size)
{

	unsigned char preimage[P2PKH_PREIMAGE_SIZE];
	unsigned char *p = preimage;
	size_t cb = 0;
	
	if(input_index >= rawtx->in_count) return -1;
	
	segwit_raw_txin_t * txins = &rawtx->raw_txin[input_index];
//	satoshi_txout_t	* txouts = rawtx->txouts;
	
	// copy header		
	memcpy(p, &rawtx->version, 4 + 32 + 32); 
	p += 4 + 32 + 32;
	
	// copy outpoint
	memcpy(p, &txins->outpoint, sizeof(satoshi_outpoint_t));
	p += sizeof(satoshi_outpoint_t);
	
	// copy pk_script of the input
	memcpy(p, txins->pk_script->vch, varstr_size(txins->pk_script));
	p += varstr_size(txins->pk_script);
	
	// set amount of the input
	*(int64_t *)p = txins->value; p += sizeof(int64_t);
	
	// set sequence
	*(uint32_t *)p = txins->sequence; p += sizeof(uint32_t);
	
	// copy output hash
	memcpy(p, rawtx->outputs_hash, 32); p += 32;
	
	// set lock_time
	*(uint32_t *)p = rawtx->lock_time; p += sizeof(uint32_t);
	
	// set hash_type
	*(uint32_t *)p = rawtx->hash_type; p += sizeof(uint32_t);
	
	cb = p - preimage;
	
	assert(NULL != p_image);
	unsigned char * image = *p_image;
	if(NULL == image)
	{
		image = malloc(cb);
		assert(NULL != image);
	}
	memcpy(image, preimage, cb);	
	if(NULL == *p_image) *p_image = image;
	if(p_image_size) *p_image_size = cb;	
	return 0;
}


int create_segwit_tx_preimage_for_sign(
	int32_t version,					
	json_object * inputs, 		// json array
	json_object * outputs,		// json array
	uint32_t lock_time,					
	json_object * unspent_list,	// can be NULL for full nodes
	uint32_t hash_type,			// SIGHASH_ALL: 0x01, SIGHASH_BCASH: 0x41
	unsigned char ** preimage,			// output
	size_t * p_preimage_size			// output length
)
{
	int i;
	int rc;
	int in_count = json_object_array_length(inputs);
	int out_count = json_object_array_length(outputs);
	unsigned char * rawtx = NULL;
	segwit_raw_txin_t * raw_txin = NULL;
	satoshi_txout_t * txouts = NULL;
	if(in_count < 1 || out_count < 1) 
	{
		debug_printf("invalid format: input = %d, output = %d\n", 
			in_count, out_count);
		return -1;
	}
	
	raw_txin = calloc(in_count, sizeof(segwit_raw_txin_t));	
	assert(NULL != raw_txin);
	
	txouts = calloc(out_count, sizeof(satoshi_txout_t));
	assert(NULL != txouts);
	
	for(i = 0; i < in_count; ++i)
	{		
		json_object * jitem = json_object_array_get_idx(inputs, i);
		assert(NULL != jitem);
		
		json_object * jtxid = NULL;
		json_object * jvout = NULL;
		json_object * jsequence = NULL;
		
		json_object * jamount = NULL;
		json_object * jscript = NULL;
		int cb_txid;		
		
		rc = json_object_object_get_ex(jitem, "txid", &jtxid);
		assert(rc);
		rc = json_object_object_get_ex(jitem, "vout", &jvout);
		assert(rc);
		rc = json_object_object_get_ex(jitem, "sequence", &jsequence);
		assert(rc);
		
		cb_txid = json_object_get_string_len(jtxid);
		assert(cb_txid == 64);
		cb_txid = hex2bin(
			json_object_get_string(jtxid),
			cb_txid,
			raw_txin[i].outpoint.hash);
		reverse_bytes(raw_txin[i].outpoint.hash, 32); // convert litten endian to big endian
		raw_txin[i].outpoint.index = json_object_get_int(jvout);
		raw_txin[i].sequence = (uint32_t)json_object_get_int(jsequence);
		
		rc = json_object_object_get_ex(jitem, "amount", &jamount);
		if(rc)
		{
			raw_txin[i].value = (int64_t)(json_object_get_double(jamount) * COIN);
		}
		
		rc = json_object_object_get_ex(jitem, "scriptPubKey", &jscript);
		if(rc)
		{
			raw_txin[i].pk_script = varstr_set(NULL, 
				json_object_get_string(jscript),
				json_object_get_string_len(jscript));
		}
	}
	
	for(i = 0; i < out_count; ++i)
	{
		json_object * jitem = json_object_array_get_idx(inputs, i);
		assert(NULL != jitem);
		json_object * jamount = NULL;
		json_object * jaddr = NULL;
		json_object * jscript = NULL;
		
		rc = json_object_object_get_ex(jitem, "amount", &jamount);		
		assert(rc);
		rc = json_object_object_get_ex(jitem, "address", &jaddr);
		if(!rc)
		{
			rc = json_object_object_get_ex(jitem, "script", &jscript);
		}
		assert(rc);	
	}
	
	
//~ label_exit:
	free(raw_txin);
	for(i = 0; i < out_count; ++i)
	{
		satoshi_txout_cleanup(&txouts[i]);
	}
	free(rawtx);
	
	return 0;
}
