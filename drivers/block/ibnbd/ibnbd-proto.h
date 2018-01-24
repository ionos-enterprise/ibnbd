/*
 * InfiniBand Network Block Driver
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

#ifndef IBNBD_PROTO_H
#define IBNBD_PROTO_H

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/limits.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/ib.h>

#define IBNBD_PROTO_VER_MAJOR 1
#define IBNBD_PROTO_VER_MINOR 0

#define IBNBD_PROTO_VER_STRING __stringify(IBNBD_PROTO_VER_MAJOR) "." \
			       __stringify(IBNBD_PROTO_VER_MINOR)

#ifndef IBNBD_VER_STRING
#define IBNBD_VER_STRING __stringify(IBNBD_PROTO_VER_MAJOR) "." \
			 __stringify(IBNBD_PROTO_VER_MINOR)
#endif

/* TODO: should be configurable */
#define IBTRS_PORT 1234

/**
 * enum ibnbd_msg_types - IBNBD message types
 * @IBNBD_MSG_SESS_INFO:	initial session info from client to server
 * @IBNBD_MSG_SESS_INFO_RSP:	initial session info from server to client
 * @IBNBD_MSG_OPEN:		open (map) device request
 * @IBNBD_MSG_OPEN_RSP:		response to an @IBNBD_MSG_OPEN
 * @IBNBD_MSG_IO:		block IO request operation
 * @IBNBD_MSG_CLOSE:		close (unmap) device request
 */
enum ibnbd_msg_type {
	IBNBD_MSG_SESS_INFO,
	IBNBD_MSG_SESS_INFO_RSP,
	IBNBD_MSG_OPEN,
	IBNBD_MSG_OPEN_RSP,
	IBNBD_MSG_IO,
	IBNBD_MSG_CLOSE,
};

/**
 * struct ibnbd_msg_hdr - header of IBNBD messages
 * @type:	Message type, valid values see: enum ibnbd_msg_types
 */
struct ibnbd_msg_hdr {
	__le16		type;
	__le16		__padding;
};

enum ibnbd_access_mode {
	IBNBD_ACCESS_RO,
	IBNBD_ACCESS_RW,
	IBNBD_ACCESS_MIGRATION,
};

#define _IBNBD_FILEIO  0
#define _IBNBD_BLOCKIO 1
#define _IBNBD_AUTOIO  2

enum ibnbd_io_mode {
	IBNBD_FILEIO = _IBNBD_FILEIO,
	IBNBD_BLOCKIO = _IBNBD_BLOCKIO,
	IBNBD_AUTOIO = _IBNBD_AUTOIO,
};

/**
 * struct ibnbd_msg_sess_info - initial session info from client to server
 * @hdr:		message header
 * @ver:		IBNBD protocol version
 */
struct ibnbd_msg_sess_info {
	struct ibnbd_msg_hdr hdr;
	u8		ver;
	u8		reserved[31];
};

/**
 * struct ibnbd_msg_sess_info_rsp - initial session info from server to client
 * @hdr:		message header
 * @ver:		IBNBD protocol version
 */
struct ibnbd_msg_sess_info_rsp {
	struct ibnbd_msg_hdr hdr;
	u8		ver;
	u8		reserved[31];
};

/**
 * struct ibnbd_msg_open - request to open a remote device.
 * @hdr:		message header
 * @access_mode:	the mode to open remote device, valid values see:
 *			enum ibnbd_access_mode
 * @io_mode:		Open volume on server as block device or as file
 * @device_name:	device path on remote side
 */
struct ibnbd_msg_open {
	struct ibnbd_msg_hdr hdr;
	u8		access_mode;
	u8		io_mode;
	s8		dev_name[NAME_MAX];
	u8		__padding[3];
};

/**
 * struct ibnbd_msg_close - request to close a remote device.
 * @hdr:	message header
 * @device_id:	device_id on server side to identify the device
 */
struct ibnbd_msg_close {
	struct ibnbd_msg_hdr hdr;
	__le32		device_id;
};

/**
 * struct ibnbd_msg_open_rsp - response message to IBNBD_MSG_OPEN
 * @hdr:		message header
 * @nsectors:		number of sectors
 * @device_id:		device_id on server side to identify the device
 * @queue_flags:	queue_flags of the device on server side
 * @max_hw_sectors:	max hardware sectors in the usual 512b unit
 * @max_write_same_sectors: max sectors for WRITE SAME in the 512b unit
 * @max_discard_sectors: max. sectors that can be discarded at once
 * @discard_granularity: size of the internal discard allocation unit
 * @discard_alignment: offset from internal allocation assignment
 * @physical_block_size: physical block size device supports
 * @logical_block_size: logical block size device supports
 * @max_segments:	max segments hardware support in one transfer
 * @secure_discard:	supports secure discard
 * @rotation:		is a rotational disc?
 * @io_mode:		io_mode device is opened.
 */
struct ibnbd_msg_open_rsp {
	struct ibnbd_msg_hdr	hdr;
	__le32			device_id;
	__le64			nsectors;
	__le32			max_hw_sectors;
	__le32			max_write_same_sectors;
	__le32			max_discard_sectors;
	__le32			discard_granularity;
	__le32			discard_alignment;
	__le16			physical_block_size;
	__le16			logical_block_size;
	__le16			max_segments;
	__le16			secure_discard;
	u8			rotational;
	u8			io_mode;
	u8			__padding[10];
};

/**
 * struct ibnbd_msg_io - message for I/O read/write
 * @hdr:	message header
 * @device_id:	device_id on server side to find the right device
 * @sector:	bi_sector attribute from struct bio
 * @rw:		bitmask, valid values are defined in enum ibnbd_io_flags
 * @bi_size:   number of bytes for I/O read/write
 */
struct ibnbd_msg_io {
	struct ibnbd_msg_hdr hdr;
	__le32		device_id;
	__le64		sector;
	__le32		rw;
	__le32		bi_size;
};

#define IBNBD_OP_BITS  8
#define IBNBD_OP_MASK  ((1 << IBNBD_OP_BITS) - 1)

/**
 * enum ibnbd_io_flags - IBNBD request types from rq_flag_bits
 * @IBNBD_OP_READ:	     read sectors from the device
 * @IBNBD_OP_WRITE:	     write sectors to the device
 * @IBNBD_OP_FLUSH:	     flush the volatile write cache
 * @IBNBD_OP_DISCARD:        discard sectors
 * @IBNBD_OP_SECURE_ERASE:   securely erase sectors
 * @IBNBD_OP_WRITE_SAME:     write the same sectors many times

 * @IBNBD_F_SYNC:	     request is sync (sync write or read)
 * @IBNBD_F_FUA:             forced unit access
 */
enum ibnbd_io_flags {

	/* Operations */

	IBNBD_OP_READ		= 0,
	IBNBD_OP_WRITE		= 1,
	IBNBD_OP_FLUSH		= 2,
	IBNBD_OP_DISCARD	= 3,
	IBNBD_OP_SECURE_ERASE	= 4,
	IBNBD_OP_WRITE_SAME	= 5,

	IBNBD_OP_LAST,

	/* Flags */

	IBNBD_F_SYNC  = 1<<(IBNBD_OP_BITS + 0),
	IBNBD_F_FUA   = 1<<(IBNBD_OP_BITS + 1),

	IBNBD_F_ALL   = (IBNBD_F_SYNC | IBNBD_F_FUA)

};

static inline u32 ibnbd_op(u32 flags)
{
	return (flags & IBNBD_OP_MASK);
}

static inline u32 ibnbd_flags(u32 flags)
{
	return (flags & ~IBNBD_OP_MASK);
}

static inline bool ibnbd_flags_supported(u32 flags)
{
	u32 op;

	op = ibnbd_op(flags);
	flags = ibnbd_flags(flags);

	if (op >= IBNBD_OP_LAST)
		return false;
	if (flags & ~IBNBD_F_ALL)
		return false;

	return true;
}

static inline u32 ibnbd_to_bio_flags(u32 ibnbd_flags)
{
	u32 bio_flags;

	switch (ibnbd_op(ibnbd_flags)) {
	case IBNBD_OP_READ:
		bio_flags = REQ_OP_READ;
		break;
	case IBNBD_OP_WRITE:
		bio_flags = REQ_OP_WRITE;
		break;
	case IBNBD_OP_FLUSH:
		bio_flags = REQ_OP_FLUSH | REQ_PREFLUSH;
		break;
	case IBNBD_OP_DISCARD:
		bio_flags = REQ_OP_DISCARD;
		break;
	case IBNBD_OP_SECURE_ERASE:
		bio_flags = REQ_OP_SECURE_ERASE;
		break;
	case IBNBD_OP_WRITE_SAME:
		bio_flags = REQ_OP_WRITE_SAME;
		break;
	default:
		WARN(1, "Unknown IBNBD type: %d (flags %d)\n",
		     ibnbd_op(ibnbd_flags), ibnbd_flags);
		bio_flags = 0;
	}

	if (ibnbd_flags & IBNBD_F_SYNC)
		bio_flags |= REQ_SYNC;

	if (ibnbd_flags & IBNBD_F_FUA)
		bio_flags |= REQ_FUA;

	return bio_flags;
}

static inline u32 rq_to_ibnbd_flags(struct request *rq)
{
	u32 ibnbd_flags;

	switch (req_op(rq)) {
	case REQ_OP_READ:
		ibnbd_flags = IBNBD_OP_READ;
		break;
	case REQ_OP_WRITE:
		ibnbd_flags = IBNBD_OP_WRITE;
		break;
	case REQ_OP_DISCARD:
		ibnbd_flags = IBNBD_OP_DISCARD;
		break;
	case REQ_OP_SECURE_ERASE:
		ibnbd_flags = IBNBD_OP_SECURE_ERASE;
		break;
	case REQ_OP_WRITE_SAME:
		ibnbd_flags = IBNBD_OP_WRITE_SAME;
		break;
	case REQ_OP_FLUSH:
		ibnbd_flags = IBNBD_OP_FLUSH;
		break;
	default:
		WARN(1, "Unknown request type %d (flags %llu)\n",
		     req_op(rq), (unsigned long long)rq->cmd_flags);
		ibnbd_flags = 0;
	}

	if (op_is_sync(rq->cmd_flags))
		ibnbd_flags |= IBNBD_F_SYNC;

	if (op_is_flush(rq->cmd_flags))
		ibnbd_flags |= IBNBD_F_FUA;

	return ibnbd_flags;
}

static inline const char *ibnbd_io_mode_str(enum ibnbd_io_mode mode)
{
	switch (mode) {
	case IBNBD_FILEIO:
		return "fileio";
	case IBNBD_BLOCKIO:
		return "blockio";
	case IBNBD_AUTOIO:
		return "autoio";
	default:
		return "unknown";
	}
}

static inline const char *ibnbd_access_mode_str(enum ibnbd_access_mode mode)
{
	switch (mode) {
	case IBNBD_ACCESS_RO:
		return "ro";
	case IBNBD_ACCESS_RW:
		return "rw";
	case IBNBD_ACCESS_MIGRATION:
		return "migration";
	default:
		return "unknown";
	}
}

#endif /* IBNBD_PROTO_H */
