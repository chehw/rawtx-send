#ifndef _TX_H_
#define _TX_H_

#include <stdio.h>
#include "satoshi-protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct thin_client_ctx thin_client_ctx_t;
// int get_utxo(const satoshi_outpoint_t * outpoint, satoshi_txout_t txout);
// int create_rawtx(satoshi_txin_t ** p_txin, int txin_count, satoshi_txout_t ** p_txout, int txout_count, satoshi_tx_t ** p_tx);

thin_client_ctx_t * thin_client_init(thin_client_ctx_t * ctx, const char * serv_name, const char * port);
int thin_client_run(thin_client_ctx_t * ctx, int (* on_data)(thin_client_ctx_t * ctx, satoshi_msg_header_t * hdr, void * payload));
void thin_client_stop(thin_client_ctx_t * ctx);
void thin_client_cleanup(thin_client_ctx_t * ctx);




int thin_client_send_msg(thin_client_ctx_t * ctx, const char command[], void * payload, size_t size);

#ifdef __cplusplus
}
#endif
#endif
