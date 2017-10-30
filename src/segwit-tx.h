#ifndef _SEGWIT_TX_H_
#define _SEGWIT_TX_H_

#include <json-c/json.h>
#include "bitcoin-consensus.h"
#include "satoshi-script.h"

#define P2PKH_PREIMAGE_SIZE 182
typedef struct segwit_raw_txin
{
	union
	{
		satoshi_raw_txin_t input;
		struct
		{
			satoshi_outpoint_t outpoint;
			unsigned char sig_script[1];
			uint32_t sequence;
		}__attribute__((packed));
	};
	int64_t value;
	varstr_t * pk_script;
}segwit_raw_txin_t;

typedef struct segwit_rawtx
{	
	uint32_t version;
	uint256_t prev_outputs_hash;
	uint256_t sequence_hash;
	satoshi_outpoint_t cur_outpoint[1];	// keep for serializing	use
	
	segwit_raw_txin_t * raw_txin;
	int in_count;
	satoshi_txout_t * txouts;
	int out_count;	
	
	uint256_t outputs_hash;	
	uint32_t lock_time;
	uint32_t hash_type;
	
	json_object * j_unspent_list;	// can be null if running as fullnode with -txindex
	json_object * j_privkeys;		// can be null if only used for verifing signatures
}segwit_rawtx_t;
void segwit_rawtx_dump(segwit_rawtx_t * rawtx);

segwit_rawtx_t * segwit_rawtx_init(segwit_rawtx_t * rawtx, 
	int32_t version,
	json_object * j_inputs,
	json_object * j_outputs,
	uint32_t lock_time,
	uint32_t hash_type,
	json_object * j_unspent_list,
	json_object * j_privkeys
);

int segwit_rawtx_generate_preimage(segwit_rawtx_t * rawtx, 
	int input_index, 
	unsigned char ** p_image, 
	size_t * p_image_size);


int create_segwit_tx_preimage_for_sign(
	int32_t version,					
	json_object * inputs, 		// json array
	json_object * outputs,		// json array
	uint32_t lock_time,					
	json_object * unspent_list,	// can be NULL for full nodes
	uint32_t hash_type,			// SIGHASH_ALL: 0x01, SIGHASH_BCASH: 0x41
	unsigned char ** preimage,			// output
	size_t * p_preimage_size			// output length
);
#endif
