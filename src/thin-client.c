/*
 * tx.c
 * 
 * Copyright 2017 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netdb.h>
#include "utils.h"
#include "satoshi-protocol.h"
#include "sha256.h"
#include "ripemd160.h"

#include "thin-client.h"
#include "shared_ptr.h"

#define THIN_CLIENT_BUFFER_SIZE (256 * 1024 * 1024)
typedef struct thin_client_buffer
{
	unsigned char * data;
	size_t max_size;
	ssize_t start_pos;
	ssize_t end_pos;
	ssize_t length;
	pthread_mutex_t mutex;
}thin_client_buffer_t;

thin_client_buffer_t * thin_client_buffer_init(thin_client_buffer_t * buffer, size_t max_size)
{
	if(max_size == 0) max_size = THIN_CLIENT_BUFFER_SIZE;
	if(NULL == buffer)
	{
		buffer = shared_ptr_malloc(sizeof(thin_client_buffer_t));
		assert(NULL != buffer);
		
	}
	memset(buffer, 0, sizeof(thin_client_buffer_t));
	buffer->data = shared_ptr_malloc(max_size);
	assert(NULL != buffer->data);
	buffer->max_size = max_size;
	buffer->start_pos = 0;
	buffer->end_pos = 0;	
	buffer->length = 0;
	debug_printf("buf->max_size = %ld\n", buffer->max_size);
	
	pthread_mutex_init(&buffer->mutex, NULL);
	return buffer;
}
void thin_client_buffer_cleanup(thin_client_buffer_t * buffer)
{
	if(buffer)
	{
		if(buffer->data) shared_ptr_free(buffer->data);
		pthread_mutex_destroy(&buffer->mutex);
		shared_ptr_free(buffer);
	}
}

int thin_client_buffer_push(thin_client_buffer_t * buffer, const unsigned char * in_data, size_t size)
{
//	debug_printf("in_data = %p, size = %ld\n", in_data, size);
	assert((buffer->length + size) < buffer->max_size);
	unsigned char * p_start = buffer->data + buffer->end_pos;
	ssize_t cb_left = -1;
	ssize_t cb = size;
	
//	dump_line(stdout, "in_data", in_data, size);
	
	//~ debug_printf("max_size: %ld, buf.length = %ld, buf.start_pos = %ld, buf.end_pos = %ld\n", 
		//~ buffer->max_size,
		//~ buffer->length, 
		//~ buffer->start_pos,
		//~ buffer->end_pos);
		
	if((buffer->end_pos + size) > buffer->max_size)
	{
		cb = buffer->max_size - buffer->end_pos;
		cb_left = size - cb;
	}
	assert(cb_left < buffer->start_pos);
	
//	debug_printf("cb = %ld, cb_left = %ld\n", cb, cb_left);
	if(cb) memcpy(p_start, in_data, cb);
	if(cb_left > 0)
	{
		memcpy(buffer, in_data + cb, cb_left);
	}
	
	buffer->length += size;
	buffer->end_pos += size;
	if(buffer->end_pos >= buffer->max_size) buffer->end_pos -= buffer->max_size;
	return 0;
}

ssize_t thin_client_buffer_pop(thin_client_buffer_t * buffer, unsigned char * out_data, size_t size)
{
	if(size > buffer->length) size = buffer->length;
	ssize_t cb = 0;
	ssize_t cb_left = 0;
	if(buffer->start_pos > buffer->end_pos)
	{
		cb = buffer->max_size - buffer->start_pos;
		if(cb < size)
		{
			cb_left = size - cb;
		}
	}else
	{
		cb = size;
	}
	if(out_data)
	{
		if(cb) memcpy(out_data, buffer->data + buffer->start_pos, cb);
		if(cb_left) memcpy(out_data + cb, buffer, cb_left);	
	}
	buffer->length -= size;
	buffer->start_pos += size;
	if(buffer->start_pos > buffer->max_size) buffer->start_pos -= buffer->max_size;
	
	{
		// check length
		ssize_t length = buffer->end_pos - buffer->start_pos;
		if(length < 0) length += buffer->max_size;
		assert(length == buffer->length);
	}
	return size;
}





typedef struct thin_client_ctx
{
	int fd;
	struct pollfd pfd[1];
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int quit;
	uint32_t magic;
	int (* on_data)(thin_client_ctx_t * ctx, satoshi_msg_header_t * hdr, void * payload);
	
	pthread_t th[1];	
	pthread_mutex_t mutex;
	
	thin_client_buffer_t in_buf;
	thin_client_buffer_t out_buf;
	
	
	unsigned char * out_buffer;
	size_t out_buffer_size;
	ssize_t out_buffer_start_pos; 
	ssize_t	out_buffer_end_pos;
}thin_client_ctx_t;

static inline void thin_client_lock(thin_client_ctx_t * ctx)
{
	pthread_mutex_lock(&ctx->mutex);
}
static inline void thin_client_unlock(thin_client_ctx_t * ctx)
{
	pthread_mutex_unlock(&ctx->mutex);
}

int thin_client_send_msg(thin_client_ctx_t * ctx, const char command[12], void * payload, size_t size)
{
	int fd = ctx->fd;
	uint256_t hash;
	satoshi_msg_header_t hdr[1];
	memset(hdr, 0, sizeof(hdr));
	hdr->magic = ctx->magic;
	strncpy(hdr->command, command, sizeof(hdr->command));
	hdr->size = size;
	hash256(payload, size, hash);
	memcpy(hdr->checksum, hash, 4);
	
	debug_printf("[%s]: size = %u\n", hdr->command, hdr->size);
	
	int count = 1;
	//~ struct pollfd pfd[1];
	//~ memset(&pfd, 0, sizeof(pfd));
	struct iovec iov[2];
	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(satoshi_msg_header_t);
	if(payload && size > 0)
	{
		iov[1].iov_base = payload;
		iov[1].iov_len = size;
		++count;
	}
	ssize_t cb = writev(fd, iov, count);
	if(cb < 0)
	{
		perror("writev");
		return -1;
	}
	if(cb != (sizeof(satoshi_msg_header_t) + size))
	{
		debug_printf("ERROR: invalid write size %ld\n", cb);
		return -1;
	}
	printf("writev: cb = %ld\n", cb);	
	return 0;
}

static int try_connect(int fd, struct sockaddr * addr, socklen_t addrlen)
{
	int rc;
	struct pollfd pfd[1];
	memset(pfd, 0, sizeof(struct pollfd));
	pfd->fd = fd;
	pfd->events = POLLOUT;
	
	struct timespec ts;
	double start_time;
	double end_time;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	start_time = ((double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0) * 1000.0;
	rc = connect(fd, addr, addrlen);
	int done = 1;
//	while(1)
//	{
	if(rc)
	{
		if(errno == EINPROGRESS) // async connect
		{
			done = 0;
		}else
		{
			printf("errno: %d\n", errno);
			perror("connect");
			
			return -1;
		}
	}
	if(done) return 0;
	rc = poll(pfd, 1, 5000); // 
	if(-1 == rc)
	{
		perror("poll");
		return -1;
	}else if(0 == rc)
	{
		// timeout
		debug_printf("poll timeout\n");
		return -1;
	}
	
	clock_gettime(CLOCK_MONOTONIC, &ts);
	end_time = ((double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0) * 1000.0;
	printf("connection time: %g\n", (end_time - start_time));
	
	int err_code = 0;
	socklen_t len = sizeof(int);
	rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err_code, &len);
	if(-1 != rc)
	{
		if(0 == err_code)
		{
			return 0;	
		}
		debug_printf("err_code: %d\n", err_code);
	}
	return -1;
				
//	}
}

thin_client_ctx_t * thin_client_init(thin_client_ctx_t * ctx, const char * serv_name, const char * port)
{
	debug_printf("ctx = %p\n", ctx);
	int rc;
	int fd = -1;
	struct addrinfo hints, * serv_info, *p;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(serv_name, port, &hints, &serv_info);
	if(rc)
	{
		debug_printf("getaddrinfo() failed: %s\n",
			gai_strerror(rc));
		exit(-1);
	}
	
	for(p = serv_info; p != NULL; p = p->ai_next)
	{
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(-1 == fd) continue;
		chutil_make_non_blocking(fd);
		rc = try_connect(fd, p->ai_addr, p->ai_addrlen);
		if(0 == rc) break;
		close(fd);
	}
	
	if(NULL == p)
	{
		freeaddrinfo(serv_info);
		exit(-1);
	}
	if(NULL == ctx)
	{
		ctx = shared_ptr_malloc(sizeof(thin_client_ctx_t));
		assert(NULL != ctx);
		
	}
	memset(ctx, 0, sizeof(thin_client_ctx_t));
	
	
	ctx->fd = fd;
	pthread_mutex_init(&ctx->mutex, NULL);
	
	memcpy(&ctx->magic, SATOSHI_MAGIC_MAIN, 4);
	
	thin_client_buffer_init(&ctx->in_buf, (1 << 24));
	thin_client_buffer_init(&ctx->out_buf, (1 << 24));
	
	memcpy(&ctx->addr, p->ai_addr, p->ai_addrlen);
	ctx->addrlen = p->ai_addrlen;
	
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	rc = getnameinfo(p->ai_addr, p->ai_addrlen, 
		hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		NI_NUMERICHOST | NI_NUMERICSERV);
		
	if(0 == rc)
	{
		debug_printf("Connected to [%s:%s]\n", hbuf, sbuf);
	}	
	
	freeaddrinfo(serv_info);
	
	
	
	return ctx;
}
void thin_client_stop(thin_client_ctx_t * ctx)
{
	ctx->quit = 1;
}

void thin_client_cleanup(thin_client_ctx_t * ctx)
{
	debug_printf("ctx = %p\n", ctx);
	if(ctx)
	{
		ctx->quit = 1;
		void * exit_code = NULL;
		pthread_join(ctx->th[0], &exit_code);
		debug_printf("exit_code: %ld\n", (long)exit_code);
		if(ctx->fd > 0)
		{
			close(ctx->fd);
			ctx->fd = -1;
		}
		
		if(ctx->out_buffer) free(ctx->out_buffer);
		ctx->out_buffer = NULL;
		ctx->out_buffer_start_pos = 0;
		ctx->out_buffer_end_pos = 0;
		
		pthread_mutex_destroy(&ctx->mutex);
		
		shared_ptr_free(ctx);
	}
}


//~ static int network_gettx(int fd, const unsigned char tx_hash, satoshi_tx_t ** p_tx)
//~ {
	
	//~ return 0;
//~ }


//~ int get_utxo(const satoshi_outpoint_t * outpoint, satoshi_txout_t txout)
//~ {
	
	//~ return 0;
//~ }

//~ int create_rawtx(satoshi_txin_t ** p_txin, int txin_count, satoshi_txout_t ** p_txout, int txout_count, satoshi_tx_t ** p_tx)
//~ {
	//~ return 0;
//~ }

static int on_recv(thin_client_ctx_t * ctx)
{
//	debug_printf("ctx = %p\n", ctx);
	unsigned char buf[4096];
	
	thin_client_buffer_t * in_buf = &ctx->in_buf;
	
	ssize_t cb;
	int done = 0;
	while(!ctx->quit)
	{		
		cb = read(ctx->fd, buf, sizeof(buf));
		printf("cb = %d\n", (int)cb);
		if(cb <= 0)
		{
			if(cb < 0)
			{
				if(errno == EAGAIN || errno == EWOULDBLOCK)
				{
					break;
				}
				done = 1;
			}
			else if(0 == cb)
			{				
				debug_printf("remote close connection\n");
				done = 1;
			}
			break;
		}
		thin_client_buffer_push(in_buf, buf, cb);
		if(in_buf->length >= 24)
		{
		//	dump_line(stdout, "in_buf", in_buf->data, in_buf->length);
			satoshi_msg_header_t * hdr = (satoshi_msg_header_t *)(in_buf->data + in_buf->start_pos);			
			if(memcmp(&hdr->magic, SATOSHI_MAGIC_MAIN, 4) != 0)
			{
				debug_printf("ERROR: invalid magic number: %.8x\n", hdr->magic);
				done = 1;
				break;
			}
			if(hdr->size > (1 << 24))
			{
				debug_printf("ERROR: invalid length: %u\n", hdr->size);
				done = 1;
				break;
			}
			
			if(in_buf->length >= (hdr->size + 24))
			{
				
				unsigned char * out_data = shared_ptr_malloc(hdr->size + 24);
				assert(NULL != out_data);
				thin_client_buffer_pop(in_buf, out_data, hdr->size + 24);
				
				hdr = (satoshi_msg_header_t *)out_data;				
				if(ctx->on_data) ctx->on_data(ctx, hdr, hdr->payload);
				if(out_data) shared_ptr_free(out_data);
				printf("freed\n");
				
			}
			
		}
		
	}	
	if(done) ctx->quit = 1;
	return done;
}
static int send_version(int fd);
static int on_send(thin_client_ctx_t * ctx)
{
	debug_printf("ctx = %p\n", ctx);
	send_version(ctx->fd);
	return 0;
}


static void * thin_client_run_thread(void * user_data)
{
	thin_client_ctx_t * ctx = (thin_client_ctx_t *)user_data;
	debug_printf("ctx = %p\n", ctx);
	int rc;
	int timeout = 1000;
	int send_done = 0;
	while(!ctx->quit)
	{
		struct pollfd pfd[1] = {0};
		thin_client_lock(ctx);
		memcpy(pfd, ctx->pfd, sizeof(ctx->pfd));
		thin_client_unlock(ctx);
		
		pfd[0].fd = ctx->fd;
		pfd[0].events |= POLLIN | (send_done?0:POLLOUT);
		
		rc = poll(pfd, 1, timeout);
		if(-1 == rc) 
		{
			debug_printf("poll() failed: %s\n", strerror(errno));
			pthread_exit((void *)(long)-1);
		}else if(0 == rc)
		{
			// timeout
		//	debug_printf("timeout...\n");
			continue;
		}
		if((pfd[0].revents & POLLERR) ||
			(pfd[0].revents & POLLRDHUP) ||
			(pfd[0].revents & POLLHUP))
		{
			// error
			debug_printf("ERROR: pfd[0].events = %d\n", pfd[0].events);
			break;
		}
			
		
		if((pfd[0].revents & POLLIN) || (pfd[0].revents & POLLOUT))
		{
			if(pfd[0].revents & POLLIN) 
			{
				if(on_recv(ctx) != 0) break;
			}
			if (pfd[0].revents & POLLOUT)
			{
			
				if(on_send(ctx) != 0) break;
				send_done = 1;
			}
		}		
		else
		{
			debug_printf("ERROR: pfd[0].events = %d\n", pfd[0].revents);
		}
			
	}
	debug_printf("pthread_exit() = %d\n", 0);
	thin_client_stop(ctx);
	pthread_exit((void *)(long)0);
}



int thin_client_run(thin_client_ctx_t * ctx, int (* on_data)(thin_client_ctx_t * ctx, satoshi_msg_header_t * hdr, void * payload))
{
	debug_printf("ctx = %p\n", ctx);
	int rc;
	
	ctx->pfd[0].fd = ctx->fd;
	ctx->pfd[0].events = POLLIN;
	
	if(on_data) ctx->on_data = on_data;
	rc = pthread_create(ctx->th, NULL, thin_client_run_thread, ctx);
	if(rc)
	{
		perror("pthread_create()");
		return -1;
	}
	
	
	
	return 0;
}
const uint32_t testnet_magic = 0x0709110B;
const uint32_t mainnet_magic = 0xD9B4BEF9;

static const unsigned char myip[16] = "\x00\x00\x00\x00"
									  "\x00\x00\x00\x00"
									  "\x00\x00\xFF\xFF"
									  "\x00\x00\x00\x00";
static unsigned short myport = 8333;

#define NODE_BITCOIN_CASH  (1 << 5)

static int send_version(int fd)
{
	struct timespec ts;
	satoshi_msg_header_t hdr = {0};
#define SATOSHI_VERSION_SIZE ((unsigned char *)&((satoshi_version_t *)NULL)->user_agent - (unsigned char *)0)

	satoshi_version_t * ver = calloc(1, sizeof(satoshi_version_t) + 100);
	clock_gettime(CLOCK_REALTIME, &ts);
	hdr.magic = mainnet_magic;
	strncpy(hdr.command, "version", sizeof(hdr.command));
	
	ver->version = 70014;
	ver->services = NODE_NETWORK | NODE_WITNESS;
	ver->timestamp = (int64_t)ts.tv_sec;
	
	ver->addr_recv.services = ver->services;
	memcpy(&ver->addr_recv.ip, myip, 16);
	ver->addr_recv.port = htons(myport);
	
	//~ ver->addr_from.services = satoshi_service_flags;
	//~ memset(&ver->addr_from.ip, 0, 16);
	//~ ver->addr_from.port = htons(0);
	
	ver->nonce = (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
	varint_set((varint_t *)&ver->user_agent, sizeof("/Satoshi:0.14.2/") - 1);
	
	printf("size of user_agent: %ld\n", sizeof("/Satoshi:0.14.2/") - 1);
	
	varstr_set(&ver->user_agent, "/Satoshi:0.14.2/", sizeof("/Satoshi:0.14.2/") - 1);
	ssize_t vstr_size = varstr_size(&ver->user_agent);	
	debug_printf("user_agent(%d): %s\n", 
		(int)vstr_size, 
		varstr_get(&ver->user_agent));
	
	
	hdr.size = SATOSHI_VERSION_SIZE + vstr_size + 4 + 1;
	
	int32_t * p_start_height = (int32_t *)((unsigned char *)&ver->user_agent + vstr_size);
	*p_start_height = 1;
	
	int8_t * p_relay = (int8_t *)((unsigned char *)&ver->user_agent + vstr_size + 4);
	*p_relay = 1;
	
	uint256_t hash;
	hash256(ver, hdr.size, hash);	
	memcpy(hdr.checksum, hash, 4);
	
	int n = write(fd, &hdr, sizeof(hdr));
	printf("write hdr: n = %d\n", n);
	n = write(fd, ver, (int)hdr.size);
	printf("write version: n = %d\n", n);
	
	satoshi_version_dump(ver);
	
	free(ver);
	return 0;
}
