/*
 * wallet.c
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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "app.h"
#include <assert.h>

#include "base58.h"

#include "utils.h"
#include "satoshi-protocol.h"
#include "satoshi-network.h"

#include "keys.h"
#include "shared_ptr.h"
#include "bitcoin-consensus.h"
#include "satoshi-script.h"

#include "segwit-tx.h"

#ifdef _HAS_SHELL
#include "shell/shell.h"
#endif

#define _TEST
app_ctx_t g_app[1];
shell_param_t g_shell[1];

static int init_proc(app_ctx_t * app, int * p_argc, char *** p_argv);
static int main_proc(app_ctx_t * app);
static void cleanup(app_ctx_t * app);

static void bcc_raw_tx_send_test1();
static void bcc_raw_tx_send_test2();

int main(int argc, char **argv)
{
	int rc = 0;
#if defined(_TEST)
	if(1) bcc_raw_tx_send_test1();
	else  bcc_raw_tx_send_test2();
	return 0;
#endif	

#if defined(_HAS_SHELL)
	shell_param_t * shell = &g_shell[0];	
	app_ctx_t * app = app_new(&g_app[0], init_proc, main_proc, cleanup, shell);
	assert(NULL != app);
	
	rc = app->init(app, &argc, &argv);
	assert(0 == rc);
	
	rc = app->main(app);
	log_printf("app->main() = %d", rc);
	
	app->cleanup(app);
#endif

	return rc;
}

static int init_proc(app_ctx_t * app, int * p_argc, char *** p_argv)
{
	shell_param_t * shell = (shell_param_t *)app->user_data;
	shell = shell_init_with_args(shell, p_argc, p_argv, app);
	
	printf("magic: 0x%.8x\n", app->network_magic);
	shell_init_windows(shell, NULL);
	
	return 0;
}

static int main_proc(app_ctx_t * app)
{
	shell_param_t * shell = (shell_param_t *)app->user_data;
	debug_printf("app=%p", app);
	shell_run(shell);
	return 0;
}

static void cleanup(app_ctx_t * app)
{
	shell_param_t * shell = (shell_param_t *)app->user_data;
	debug_printf("app=%p", app);
	shell_cleanup(shell);
	return;
}

static secp256k1_context *  secp;
static void bcc_raw_tx_send_test1()
{
	int rc;
	static const char unspent_list[] = "["			
			"{"
				"\"txid\": \"376c6b12bcfd0aa0e076d0d8bcfea8de5c2d2c741aee1d4ab2f58bc65abc4183\","
				"\"vout\": 0,"
				"\"sequence\": 4294967295,"
				
				"\"address\": \"14988DnhKffGmvjAEZ5TdDJqNnJ8XRf4YG\","
				"\"scriptPubKey\": \"76a9142271a6fb3fe5183d92ef25f1d2391278ab62aa7388ac\","
				"\"amount\": 37.63000000,"
			"},"
			"{"
				"\"txid\": \"12d1636cf7a6a9e2ff964ed70ec64024f60e5fb0d7adae339e14759e55615a47\","
				"\"vout\": 0,"
				"\"sequence\": 4294967295,"
				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","				
				"\"scriptPubKey\": \"76a91452b6f262ca9fd1694eeeb4dff74265e0bc07b4b488ac\","
				"\"amount\": 0.05000000,"
			"},"
		"]";
	static const char outputs[] = "["
			"{"
				"\"amount\": 37.6298,"				
				"\"address\": \"37xx9BoJPye1LkNNACNzSU7SN5JntaxA8D\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.01,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.01,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.01,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.01,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
			"{"
				"\"amount\": 0.001,"				
				"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","	
			//	"\"address\": \"18YMa6gdq71D27teRMMmLN9tRMhVDsUP1g\","
				/* "17a91444d440c64b906b2f1c584b0b4d4d663394e94dbc87" */
			"},"
		"]";
	json_object * j_inputs;
	json_object * j_outputs;
	//~ int rc;
	segwit_rawtx_t rawtx[1];
	json_tokener * tok = json_tokener_new();
	enum json_tokener_error jerr;
	j_inputs = json_tokener_parse_ex(tok, 
		unspent_list, 
		strlen(unspent_list));
	jerr = json_tokener_get_error(tok);
	if(jerr != json_tokener_success)
	{
		printf("json_tokener_parse_ex() failed: %s\n",
			json_tokener_error_desc(jerr));
	}
	//~ j_inputs = json_tokener_parse(unspent_list);
	assert(NULL != j_inputs);
	
	j_outputs = json_tokener_parse(outputs);
	assert(NULL != j_outputs);
	
	// step 1. rawtx_init (2 txins and 15 txouts in this example)
	segwit_rawtx_init(rawtx, 
		2, 
		j_inputs, j_outputs, 
		0, 		// locktime
		0x41,	// SIGHASH_FORKID
		NULL, 	// addtional unspent list
		NULL	// private keys
		);
	
	printf("==== dump rawtx ====\n");
	segwit_rawtx_dump(rawtx);
	
	// step 2. prepare preimage for signature hash
	uint256_t msg_hash[2];
	unsigned char preimage[P2PKH_PREIMAGE_SIZE] = "";
	unsigned char * p_image = preimage;	
	
	// step 2-1-1. generate txin[0]'s preimage
	size_t cb_image = sizeof(preimage);	
	rc = segwit_rawtx_generate_preimage(rawtx, 0, &p_image, &cb_image);
	assert(0 == rc);
	printf("cb_image = %d\n", (int)cb_image);
	dump_line(stdout, "preimage 0", preimage, cb_image);
	// step 2-1-2. calc msg_hash[0]	
	hash256(preimage, cb_image, msg_hash[0]);
	printf("hash 0: "); dump(msg_hash[0], 32);
	
	// step 2-2-1. generate txin[1]'s preimage
	memset(preimage, 0, sizeof(preimage));
	cb_image = sizeof(preimage);	
	rc = segwit_rawtx_generate_preimage(rawtx, 1, &p_image, &cb_image);
	assert(0 == rc);	
	printf("cb_image = %d\n", (int)cb_image);	
	dump_line(stdout, "preimage 1", preimage, cb_image);	
	// step 2-1-2. calc msg_hash[1]	
	hash256(preimage, cb_image, msg_hash[1]);
	printf("hash 1: "); dump(msg_hash[1], 32);
	
	// step 3. ecdsa sign
	secp256k1_pubkey ecpub[2];
	secp256k1_ecdsa_signature ecsig[2];
	memset(ecpub, 0, sizeof(ecpub));
	memset(ecsig, 0, sizeof(ecsig));
	
	ch_keys_t keys[2];
	memset(keys, 0, sizeof(keys));	
	
	char wif[2][64] = {
		"Lxxxxx...(privkey1-wif)",	// WIF format of private key 1 
		"Mxxxxx...(privkey2-wif)"   // WIF format of private key 2
	};
	
	char addr[2][100] = {""};
	ssize_t cb_addr[2] = {0};
	// import private keys. 
	rc = ch_keys_privkey_import(&keys[0], wif[0]);
	assert(0 == rc);
	rc = ch_keys_privkey_import(&keys[1], wif[1]);
	assert(0 == rc);
	
	cb_addr[0] = ch_keys_pubkey_to_addr(&keys[0], 0, addr[0], sizeof(addr[0]));
	assert(cb_addr[0] > 0);
	printf("addr[0]: %s\n", addr[0]);
	cb_addr[1] = ch_keys_pubkey_to_addr(&keys[1], 0, addr[1], sizeof(addr[1]));
	assert(cb_addr[1] > 0);
	printf("addr[1]: %s\n", addr[1]);
	
	rc = secp256k1_ecdsa_sign(secp, &ecsig[0], msg_hash[0], keys[0].secret,
		secp256k1_nonce_function_rfc6979, NULL);
	assert(rc);
	rc = secp256k1_ecdsa_sign(secp, &ecsig[1], msg_hash[1], keys[1].secret,
		secp256k1_nonce_function_rfc6979, NULL);
	assert(rc);
	
	
	// step 4. verify signature
	rc = secp256k1_ecdsa_verify(secp, &ecsig[0], msg_hash[0], keys[0].pubkey);
	assert(rc);
	printf("verify sig 0: %d\n", rc);
	
	rc = secp256k1_ecdsa_verify(secp, &ecsig[1], msg_hash[1], keys[1].pubkey);
	printf("verify sig 1: %d\n", rc);
	
	// clear secret keys */
	memset(keys[0].secret, 0, sizeof(keys[0].secret));
	memset(keys[1].secret, 0, sizeof(keys[1].secret));
	memset(wif, 0, sizeof(wif));
	
	unsigned char sig_der[2][100];
	size_t cb_sig[2] = {100, 100};
	memset(sig_der, 0, sizeof(sig_der));
	
	rc = secp256k1_ecdsa_signature_serialize_der(secp, sig_der[0], &cb_sig[0], &ecsig[0]);
	assert(rc);
	dump_line(stdout, "sig[0]", sig_der[0], cb_sig[0]);
	
	rc = secp256k1_ecdsa_signature_serialize_der(secp, sig_der[1], &cb_sig[1], &ecsig[1]);
	assert(rc);
	dump_line(stdout, "sig[1]", sig_der[1], cb_sig[1]);
	
	//~ ch_keys_cleanup(&keys[0]);
	//~ ch_keys_cleanup(&keys[1]);
	
	// dump pubkey and signature info
	unsigned char pubkey_data[2][65];
	size_t cb_pubkey[2] = {65, 65};
	memset(pubkey_data, 0, sizeof(pubkey_data));
	
	rc = secp256k1_ec_pubkey_serialize(secp, pubkey_data[0], &cb_pubkey[0], 
		keys[0].pubkey, SECP256K1_EC_COMPRESSED);
	assert(rc);
	dump_line(stdout, "pubkey[0]", pubkey_data[0], cb_pubkey[0]);
	
	rc = secp256k1_ec_pubkey_serialize(secp, pubkey_data[1], &cb_pubkey[1], 
		keys[1].pubkey, SECP256K1_EC_COMPRESSED);
	assert(rc);
	dump_line(stdout, "pubkey[1]", pubkey_data[1], cb_pubkey[1]);
	
	
	// step 5. construct signed tx
	static unsigned char signed_tx[65535] = {0};
	unsigned char * p = signed_tx;
	
	// version	
	*(int32_t *)p = rawtx->version; p += sizeof(int32_t);
	
	// write txin count
	varint_set((varint_t *)p, rawtx->in_count);
	p += varint_size((varint_t *)p);
	
	assert(rawtx->in_count == 2);
	int i;
	for(i = 0; i < rawtx->in_count; ++i)
	{
		// copy outpoint
		memcpy(p, &rawtx->raw_txin[i].outpoint, sizeof(satoshi_outpoint_t));
		p += sizeof(satoshi_outpoint_t);
		
		// add sig script
		int sig_size = cb_sig[i] + 1 + varint_calc_size(cb_sig[i] + 1);
		int pub_size = cb_pubkey[i] + varint_calc_size(cb_pubkey[i]);
		int cb_script = sig_size + pub_size; 
		// serialize sig_script size
		varint_set((varint_t *)p, cb_script); 
		p += varint_size((varint_t *)p);
		
		varint_set((varint_t *)p, cb_sig[i] + 1);
		p += varint_size((varint_t *)p);
		memcpy(p, sig_der[i], cb_sig[i]);
		p += cb_sig[i];
		*p++ = (unsigned char)(rawtx->hash_type & 0xff);
		
		varint_set((varint_t *)p, cb_pubkey[i]);
		p += varint_size((varint_t *)p);
		memcpy(p, pubkey_data[i], cb_pubkey[i]);
		p += cb_pubkey[i];
		
		// write sequence
		*(uint32_t *)p = rawtx->raw_txin[i].sequence;
		p += sizeof(uint32_t);
	}
	
	// write txout count
	varint_set((varint_t *)p, rawtx->out_count);
	p += varint_size((varint_t *)p);
	
	for(i = 0; i < rawtx->out_count; ++i)
	{
		// write value
		*(int64_t *)p = rawtx->txouts[i].value;
		p += sizeof(int64_t);
		
		// write pk_script
		int cb_script = varstr_size(rawtx->txouts[i].pk_script);
		memcpy(p, rawtx->txouts[i].pk_script->vch, cb_script);
		p += cb_script;
	}
	
	// write lock_time
	*(uint32_t *)p = rawtx->lock_time;
	p += sizeof(uint32_t);
	
	size_t cb = p - signed_tx;
	printf("cb = %d\n", (int)cb);
	
	dump_line(stdout, "tx", signed_tx, cb);
	
	uint256_t txid;	
	hash256(signed_tx, cb, txid);
	dump_line(stdout, "txid", txid, 32);
	
	// step 6. broadcase tx inv
	// thin_client_send_msg();
	
	return;
}

static void bcc_raw_tx_send_test2()
{
	json_object * j_root = NULL;
	json_object * j_inputs = NULL;
	json_object * j_outputs = NULL;
	int rc;
	segwit_rawtx_t rawtx[1];
	
	// load info from json file
	FILE * fp = fopen("data/inputs.json", "r");
	assert(NULL != fp);
	size_t cb_file = 0;
	fseek(fp, 0, SEEK_END);
	cb_file = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("file size: %ld\n", cb_file);
	char buf[4096] = "";
	ssize_t cb;
	cb = fread(buf, 1, sizeof(buf), fp);
	printf("bytes read: %ld\n", cb);
	
	json_tokener * tok = json_tokener_new();
	enum json_tokener_error jerr;
	j_root = json_tokener_parse_ex(tok, buf, cb);
	jerr = json_tokener_get_error(tok);
	printf("json err: %s\n", json_tokener_error_desc(jerr));
	
	//~ j_root = json_object_from_file("data/inputs.json");
	assert(NULL != j_root);
	
	rc = json_object_object_get_ex(j_root, "inputs", &j_inputs);
	assert(rc && j_inputs);
	
	rc = json_object_object_get_ex(j_root, "outputs", &j_outputs);
	assert(rc && j_outputs);
	
	segwit_rawtx_init(rawtx, 
		2, 
		j_inputs, j_outputs, 
		0, 
		0x41,
		NULL, NULL);
	
	printf("==== dump rawtx ====\n");
	segwit_rawtx_dump(rawtx);
	
	uint256_t msg_hash[2];
	unsigned char preimage[P2PKH_PREIMAGE_SIZE] = "";
	unsigned char * p_image = preimage;
	size_t cb_image = sizeof(preimage);
	rc = segwit_rawtx_generate_preimage(rawtx, 0, &p_image, &cb_image);
	assert(0 == rc);
	
	printf("cb_image = %d\n", (int)cb_image);
	dump_line(stdout, "preimage 0", preimage, cb_image);
	hash256(preimage, cb_image, msg_hash[0]);
	printf("hash 0: "); dump(msg_hash[0], 32);
	
	
	memset(preimage, 0, sizeof(preimage));
	cb_image = sizeof(preimage);	
	rc = segwit_rawtx_generate_preimage(rawtx, 1, &p_image, &cb_image);
	assert(0 == rc);
	
	printf("cb_image = %d\n", (int)cb_image);
	dump_line(stdout, "preimage 1", preimage, cb_image);
	hash256(preimage, cb_image, msg_hash[1]);
	printf("hash 1: "); dump(msg_hash[1], 32);
	
	secp256k1_pubkey ecpub[2];
	secp256k1_ecdsa_signature ecsig[2];
	memset(ecpub, 0, sizeof(ecpub));
	memset(ecsig, 0, sizeof(ecsig));
	
	ch_keys_t keys[2];
	memset(keys, 0, sizeof(keys));
	
	// private keys
	const char * wif[2] = {
		"",
		""
	};
	char addr[2][100] = {""};
	ssize_t cb_addr[2] = {0};
	rc = ch_keys_privkey_import(&keys[0], wif[0]);
	assert(0 == rc);
	rc = ch_keys_privkey_import(&keys[1], wif[1]);
	assert(0 == rc);
	
	cb_addr[0] = ch_keys_pubkey_to_addr(&keys[0], 0, addr[0], sizeof(addr[0]));
	assert(cb_addr[0] > 0);
	printf("addr[0]: %s\n", addr[0]);
	cb_addr[1] = ch_keys_pubkey_to_addr(&keys[1], 0, addr[1], sizeof(addr[1]));
	assert(cb_addr[1] > 0);
	printf("addr[1]: %s\n", addr[1]);
	
	rc = secp256k1_ecdsa_sign(secp, &ecsig[0], msg_hash[0], keys[0].secret,
		secp256k1_nonce_function_rfc6979, NULL);
	assert(rc);
	rc = secp256k1_ecdsa_sign(secp, &ecsig[1], msg_hash[1], keys[1].secret,
		secp256k1_nonce_function_rfc6979, NULL);
	assert(rc);
	
	
	
	rc = secp256k1_ecdsa_verify(secp, &ecsig[0], msg_hash[0], keys[0].pubkey);
	assert(rc);
	printf("verify sig 0: %d\n", rc);
	
	rc = secp256k1_ecdsa_verify(secp, &ecsig[1], msg_hash[1], keys[1].pubkey);
	printf("verify sig 1: %d\n", rc);
	
	memset(keys[0].secret, 0, sizeof(keys[0].secret));
	memset(keys[1].secret, 0, sizeof(keys[1].secret));
	
	unsigned char sig_der[2][100];
	size_t cb_sig[2] = {100, 100};
	memset(sig_der, 0, sizeof(sig_der));
	
	rc = secp256k1_ecdsa_signature_serialize_der(secp, sig_der[0], &cb_sig[0], &ecsig[0]);
	assert(rc);
	dump_line(stdout, "sig[0]", sig_der[0], cb_sig[0]);
	
	rc = secp256k1_ecdsa_signature_serialize_der(secp, sig_der[1], &cb_sig[1], &ecsig[1]);
	assert(rc);
	dump_line(stdout, "sig[1]", sig_der[1], cb_sig[1]);
	
	//~ ch_keys_cleanup(&keys[0]);
	//~ ch_keys_cleanup(&keys[1]);
	
	unsigned char pubkey_data[2][65];
	size_t cb_pubkey[2] = {65, 65};
	memset(pubkey_data, 0, sizeof(pubkey_data));
	
	rc = secp256k1_ec_pubkey_serialize(secp, pubkey_data[0], &cb_pubkey[0], 
		keys[0].pubkey, SECP256K1_EC_COMPRESSED);
	assert(rc);
	dump_line(stdout, "pubkey[0]", pubkey_data[0], cb_pubkey[0]);
	
	rc = secp256k1_ec_pubkey_serialize(secp, pubkey_data[1], &cb_pubkey[1], 
		keys[1].pubkey, SECP256K1_EC_COMPRESSED);
	assert(rc);
	dump_line(stdout, "pubkey[1]", pubkey_data[1], cb_pubkey[1]);
	
	// generate signed tx
	static unsigned char signed_tx[65535] = {0};
	unsigned char * p = signed_tx;
	
	// version
	*(int32_t *)p = rawtx->version; p += sizeof(int32_t);
	
	// write txin count
	varint_set((varint_t *)p, rawtx->in_count);
	p += varint_size((varint_t *)p);
	
	assert(rawtx->in_count == 2);
	int i;
	for(i = 0; i < rawtx->in_count; ++i)
	{
		// copy outpoint
		memcpy(p, &rawtx->raw_txin[i].outpoint, sizeof(satoshi_outpoint_t));
		p += sizeof(satoshi_outpoint_t);
		
		// add sig script
		int sig_size = cb_sig[i] + 1 + varint_calc_size(cb_sig[i] + 1);
		int pub_size = cb_pubkey[i] + varint_calc_size(cb_pubkey[i]);
		int cb_script = sig_size + pub_size; 
		// serialize sig_script size
		varint_set((varint_t *)p, cb_script); 
		p += varint_size((varint_t *)p);
		
		varint_set((varint_t *)p, cb_sig[i] + 1);
		p += varint_size((varint_t *)p);
		memcpy(p, sig_der[i], cb_sig[i]);
		p += cb_sig[i];
		*p++ = (unsigned char)(rawtx->hash_type & 0xff);
		
		varint_set((varint_t *)p, cb_pubkey[i]);
		p += varint_size((varint_t *)p);
		memcpy(p, pubkey_data[i], cb_pubkey[i]);
		p += cb_pubkey[i];
		
		// write sequence
		*(uint32_t *)p = rawtx->raw_txin[i].sequence;
		p += sizeof(uint32_t);
	}
	
	// write txout count
	varint_set((varint_t *)p, rawtx->out_count);
	p += varint_size((varint_t *)p);
	
	for(i = 0; i < rawtx->out_count; ++i)
	{
		// write value
		*(int64_t *)p = rawtx->txouts[i].value;
		p += sizeof(int64_t);
		
		// write pk_script
		int cb_script = varstr_size(rawtx->txouts[i].pk_script);
		memcpy(p, rawtx->txouts[i].pk_script->vch, cb_script);
		p += cb_script;
	}
	
	// write lock_time
	*(uint32_t *)p = rawtx->lock_time;
	p += sizeof(uint32_t);
	
	cb = p - signed_tx;
	printf("cb = %d\n", (int)cb);
	
	dump_line(stdout, "tx", signed_tx, cb);
	
	uint256_t txid;	
	hash256(signed_tx, cb, txid);
	dump_line(stdout, "txid", txid, 32);
	return;
}
