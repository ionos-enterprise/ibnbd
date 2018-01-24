/*
 * InfiniBand Transport Layer
 *
 * Copyright (c) 2014 - 2017 ProfitBricks GmbH. All rights reserved.
 * Authors: Fabian Holler <mail@fholler.de>
 *          Jack Wang <jinpu.wang@profitbricks.com>
 *          Kleber Souza <kleber.souza@profitbricks.com>
 *          Danil Kipnis <danil.kipnis@profitbricks.com>
 *          Roman Penyaev <roman.penyaev@profitbricks.com>
 *          Milind Dumbare <Milind.dumbare@gmail.com>
 *
 * Copyright (c) 2017 - 2018 ProfitBricks GmbH. All rights reserved.
 * Authors: Danil Kipnis <danil.kipnis@profitbricks.com>
 *          Roman Penyaev <roman.penyaev@profitbricks.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef IBTRS_H
#define IBTRS_H

#include <linux/socket.h>
#include <linux/scatterlist.h>

struct ibtrs_tag;
struct ibtrs_clt;
struct ibtrs_srv_ctx;
struct ibtrs_srv;
struct ibtrs_srv_op;

/*
 * Here goes IBTRS client API
 */

/**
 * enum ibtrs_clt_link_ev - Events about connectivity state of a client
 * @IBTRS_CLT_LINK_EV_RECONNECTED	Client was reconnected.
 * @IBTRS_CLT_LINK_EV_DISCONNECTED	Client was disconnected.
 */
enum ibtrs_clt_link_ev {
	IBTRS_CLT_LINK_EV_RECONNECTED,
	IBTRS_CLT_LINK_EV_DISCONNECTED,
};

/**
 * Source and destination address of a path to be established
 */
struct ibtrs_addr {
	struct sockaddr_storage *src;
	struct sockaddr_storage *dst;
};

typedef void (link_clt_ev_fn)(void *priv, enum ibtrs_clt_link_ev ev);
/**
 * ibtrs_clt_open() - Open a session to a IBTRS client
 * @priv:		User supplied private data.
 * @link_ev:		Event notification for connection state changes
 *	@priv:			user supplied data that was passed to
 *				ibtrs_clt_open()
 *	@ev:			Occurred event
 * @sessname: name of the session
 * @paths: Paths to be established defined by their src and dst addresses
 * @path_cnt: Number of elemnts in the @paths array
 * @port: port to be used by the IBTRS session
 * @pdu_sz: Size of extra payload which can be accessed after tag allocation.
 * @max_inflight_msg: Max. number of parallel inflight messages for the session
 * @max_segments: Max. number of segments per IO request
 * @reconnect_delay_sec: time between reconnect tries
 * @max_reconnect_attempts: Number of times to reconnect on error before giving
 *			    up, 0 for * disabled, -1 for forever
 *
 * Starts session establishment with the ibtrs_server. The function can block
 * up to ~2000ms until it returns.
 *
 * Return a valid pointer on success otherwise PTR_ERR.
 */
struct ibtrs_clt *ibtrs_clt_open(void *priv, link_clt_ev_fn *link_ev,
				 const char *sessname,
				 const struct ibtrs_addr *paths,
				 size_t path_cnt, short port,
				 size_t pdu_sz, u8 reconnect_delay_sec,
				 u16 max_segments,
				 s16 max_reconnect_attempts);

/**
 * ibtrs_clt_close() - Close a session
 * @sess: Session handler, is freed on return
 */
void ibtrs_clt_close(struct ibtrs_clt *sess);

/**
 * ibtrs_tag_from_pdu() - converts opaque pdu pointer to ibtrs_tag
 * @pdu: opaque pointer
 */
struct ibtrs_tag *ibtrs_tag_from_pdu(void *pdu);

/**
 * ibtrs_tag_to_pdu() - converts ibtrs_tag to opaque pdu pointer
 * @tag: IBTRS tag pointer
 */
void *ibtrs_tag_to_pdu(struct ibtrs_tag *tag);

enum {
	IBTRS_TAG_NOWAIT = 0,
	IBTRS_TAG_WAIT   = 1,
};

/**
 * enum ibtrs_clt_con_type() type of ib connection to use with a given tag
 * @USR_CON - use connection reserved vor "service" messages
 * @IO_CON - use a connection reserved for IO
 */
enum ibtrs_clt_con_type {
	IBTRS_USR_CON,
	IBTRS_IO_CON
};

/**
 * ibtrs_clt_get_tag() - allocates tag for future RDMA operation
 * @sess:	Current session
 * @con_type:	Type of connection to use with the tag
 * @wait:	Wait type
 *
 * Description:
 *    Allocates tag for the following RDMA operation.  Tag is used
 *    to preallocate all resources and to propagate memory pressure
 *    up earlier.
 *
 * Context:
 *    Can sleep if @wait == IBTRS_TAG_WAIT
 */
struct ibtrs_tag *ibtrs_clt_get_tag(struct ibtrs_clt *sess,
				    enum ibtrs_clt_con_type con_type,
				    int wait);

/**
 * ibtrs_clt_put_tag() - puts allocated tag
 * @sess:	Current session
 * @tag:	Tag to be freed
 *
 * Context:
 *    Does not matter
 */
void ibtrs_clt_put_tag(struct ibtrs_clt *sess, struct ibtrs_tag *tag);

typedef void (ibtrs_conf_fn)(void *priv, int errno);
/**
 * ibtrs_clt_request() - Request data transfer to/from server via RDMA.
 *
 * @dir:	READ/WRITE
 * @conf:	callback function to be called as confirmation
 * @sess:	Session
 * @tag:	Preallocated tag
 * @priv:	User provided data, passed back with corresponding
 *		@(conf) confirmation.
 * @vec:	Message that is send to server together with the request.
 *		Sum of len of all @vec elements limited to <= IO_MSG_SIZE.
 *		Since the msg is copied internally it can be allocated on stack.
 * @nr:		Number of elements in @vec.
 * @len:	length of data send to/from server
 * @sg:		Pages to be sent/received to/from server.
 * @sg_cnt:	Number of elements in the @sg
 *
 * Return:
 * 0:		Success
 * <0:		Error
 *
 * On dir=READ ibtrs client will request a data transfer from Server to client.
 * The data that the server will respond with will be stored in @sg when
 * the user receives an %IBTRS_CLT_RDMA_EV_RDMA_REQUEST_WRITE_COMPL event.
 * On dir=WRITE ibtrs client will rdma write data in sg to server side.
 */
int ibtrs_clt_request(int dir, ibtrs_conf_fn *conf, struct ibtrs_clt *sess,
		      struct ibtrs_tag *tag, void *priv, const struct kvec *vec,
		      size_t nr, size_t len, struct scatterlist *sg,
		      unsigned int sg_cnt);

/**
 * ibtrs_attrs - IBTRS session attributes
 */
struct ibtrs_attrs {
	u32	queue_depth;
	u32	max_io_size;
	u8	sessname[NAME_MAX];
};

/**
 * ibtrs_clt_query() - queries IBTRS session attributes
 *
 * Returns:
 *    0 on success
 *    -ECOMM		no connection to the server
 */
int ibtrs_clt_query(struct ibtrs_clt *sess, struct ibtrs_attrs *attr);

/*
 * Here goes IBTRS server API
 */

/**
 * enum ibtrs_srv_link_ev - Server link events
 * @IBTRS_SRV_LINK_EV_CONNECTED:	Connection from client established
 * @IBTRS_SRV_LINK_EV_DISCONNECTED:	Connection was disconnected, all
 *					connection IBTRS resources were freed.
 */
enum ibtrs_srv_link_ev {
	IBTRS_SRV_LINK_EV_CONNECTED,
	IBTRS_SRV_LINK_EV_DISCONNECTED,
};

/**
 * rdma_ev_fn():	Event notification for RDMA operations
 *			If the callback returns a value != 0, an error message
 *			for the data transfer will be sent to the client.

 *	@sess:		Session
 *	@priv:		Private data set by ibtrs_srv_set_sess_priv()
 *	@id:		internal IBTRS operation id
 *	@dir:		READ/WRITE
 *	@data:		Pointer to (bidirectional) rdma memory area:
 *			- in case of %IBTRS_SRV_RDMA_EV_RECV contains
 *			data sent by the client
 *			- in case of %IBTRS_SRV_RDMA_EV_WRITE_REQ points to the
 *			memory area where the response is to be written to
 *	@datalen:	Size of the memory area in @data
 *	@usr:		The extra user message sent by the client (%vec)
 *	@usrlen:	Size of the user message
 */
typedef int (rdma_ev_fn)(struct ibtrs_srv *sess, void *priv,
			 struct ibtrs_srv_op *id, int dir,
			 void *data, size_t datalen, const void *usr,
			 size_t usrlen);

/**
 * link_ev_fn():	Events about connective state changes
 *			If the callback returns != 0 and the event
 *			%IBTRS_SRV_LINK_EV_CONNECTED the corresponding session
 *			will be destroyed.
 *	@sess:		Session
 *	@ev:		event
 *	@priv:		Private data from user if previously set with
 *			ibtrs_srv_set_sess_priv()
 */
typedef int (link_ev_fn)(struct ibtrs_srv *sess, enum ibtrs_srv_link_ev ev,
			 void *priv);

/**
 * ibtrs_srv_open() - open IBTRS server context
 * @ops:		callback functions
 *
 * Creates server context with specified callbacks.
 *
 * Return a valid pointer on success otherwise PTR_ERR.
 */
struct ibtrs_srv_ctx *ibtrs_srv_open(rdma_ev_fn *rdma_ev, link_ev_fn *link_ev,
				     unsigned int port);

/**
 * ibtrs_srv_close() - close IBTRS server context
 * @ctx: pointer to server context
 *
 * Closes IBTRS server context with all client sessions.
 */
void ibtrs_srv_close(struct ibtrs_srv_ctx *ctx);

/**
 * ibtrs_srv_resp_rdma() - Finish an RDMA request
 *
 * @id:		Internal IBTRS operation identifier
 * @errno:	Response Code send to the other side for this operation.
 *		0 = success, <=0 error
 *
 * Finish a RDMA operation. A message is sent to the client and the
 * corresponding memory areas will be released.
 */
void ibtrs_srv_resp_rdma(struct ibtrs_srv_op *id, int errno);

/**
 * ibtrs_srv_set_sess_priv() - Set private pointer in ibtrs_srv.
 * @sess:	Session
 * @priv:	The private pointer that is associated with the session.
 */
void ibtrs_srv_set_sess_priv(struct ibtrs_srv *sess, void *priv);

/**
 * ibtrs_srv_get_sess_qdepth() - Get ibtrs_srv qdepth.
 * @sess:	Session
 */
int ibtrs_srv_get_queue_depth(struct ibtrs_srv *sess);

/**
 * ibtrs_srv_get_sess_name() - Get ibtrs_srv peer hostname.
 * @sess:	Session
 * @sessname:	Sessname buffer
 * @len:	Length of sessname buffer
 */
int ibtrs_srv_get_sess_name(struct ibtrs_srv *sess, char *sessname, size_t len);

/**
 * ibtrs_addr_to_sockaddr() - convert path string "src,dst" to sockaddreses
 * @str		string containing source and destination addr of a path
 *		separated by comma. I.e. "ip:1.1.1.1,ip:1.1.1.2". If str
 *		contains only one address it's considered to be destination.
 * @len		string length
 * @addr->dst	will be set to the destination sockadddr.
 * @addr->src	will be set to the source address or to NULL
 *		if str doesn't contain any sorce address.
 *
 * Returns zero if conversion successful. Non-zero otherwise.
 */
int ibtrs_addr_to_sockaddr(const char *str, size_t len, short port,
			   struct ibtrs_addr *addr);
#endif
