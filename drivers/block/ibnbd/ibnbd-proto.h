#ifndef __IBNBD_PROTO_H
#define __IBNBD_PROTO_H

#include <linux/limits.h>
#include "ibnbd.h"

#define IBNBD_VERSION 1

#define GCC_DIAGNOSTIC_AWARE ((__GNUC__ > 6))
#if GCC_DIAGNOSTIC_AWARE
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wpadded"
#endif

/**
 * enum ibnbd_msg_types - IBNBD message types
 * @IBNBD_MSG_SESS_INFO:	initial session info from client to server
 * @IBNBD_MSG_SESS_INFO_RSP:	initial session info from server to client
 * @IBNBD_MSG_OPEN:		open connection to ibnbd server instance
 * @IBNBD_MSG_OPEN_RSP:		response to an @IBNBD_MSG_OPEN
 * @IBNBD_MSG_READ:		request block device read operation
 * @IBNBD_MSG_REVAL:		notify client about changed device size
 *
 * Note: DO NOT REORDER THE MEMBERS OF THIS ENUM!
 * If necessary, add new members after the last one.
 */
enum ibnbd_msg_type {
	__IBNBD_MSG_MIN,
	IBNBD_MSG_SESS_INFO,
	IBNBD_MSG_SESS_INFO_RSP,
	IBNBD_MSG_OPEN,
	IBNBD_MSG_OPEN_RSP,
	IBNBD_MSG_IO,
	IBNBD_MSG_CLOSE,
	IBNBD_MSG_CLOSE_RSP,
	IBNBD_MSG_REVAL,
	__IBNBD_MSG_MAX
};

/**
 * struct ibnbd_msg_hdr - header of IBNBD messages
 * @type:	Message type, valid values see: enum ibnbd_msg_types
 */
struct ibnbd_msg_hdr {
	u16		type;
	u16		__padding;
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
 *
 * Note: DO NOT CHANGE THE ORDER OF THE MEMBERS BEFORE 'ver'
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
 *
 * Note: DO NOT CHANGE THE ORDER OF THE MEMBERS BEFORE 'ver'
 */
struct ibnbd_msg_sess_info_rsp {
	struct ibnbd_msg_hdr hdr;

	u8		ver;
	u8		reserved[31];
};

/**
 * struct ibnbd_msg_open - request to open a remote device.
 * @hdr:		message header
 * @clt_device_id:	device_id on client side to identify the device
 * @access_mode:	the mode to open remote device, valid values see:
 *			enum ibnbd_access_mode
 * @io_mode:		Open volume on server as block device or as file
 * @device_name:	device path on remote side
 */
struct ibnbd_msg_open {
	struct ibnbd_msg_hdr hdr;
	u32		clt_device_id;
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
	u32		device_id;
};

/**
 * struct ibnbd_msg_close_rsp - response to a close device message.
 * @hdr:	message header
 * @clt_device_id:	device_id on client side
 */
struct ibnbd_msg_close_rsp {
	struct ibnbd_msg_hdr hdr;
	u32		clt_device_id;
};

/**
 * struct ibnbd_msg_open_rsp - response message to IBNBD_MSG_OPEN
 * @hdr:		message header
 * @result:		0 on success or negative error code on failure
 * @clt_device_id:	device_id on client side
 * @device_id:		device_id on server side to identify the device
 * @queue_flags:	queue_flags of the device on server side
 * @max_hw_sectors:	max hardware sectors in the usual 512b unit
 * @max_write_same_sectors: max sectors for WRITE SAME in the 512b unit
 * @max_discard_sectors: max. sectors that can be discarded at once
 * @discard_zeroes_data: discarded areas are overwritten with 0?
 * @discard_granularity: size of the internal discard allocation unit
 * @discard_alignment: offset from internal allocation assignment
 * @physical_block_size: physical block size device supports
 * @logical_block_size: logical block size device supports
 * @max_segments:	max segments hardware support in one transfer
 * @nsectors:		number of sectors
 * @secure_discard:	supports secure discard
 * @rotation:		is a rotational disc?
 * @io_mode:		io_mode device is opened.
 */
struct ibnbd_msg_open_rsp {
	struct ibnbd_msg_hdr	hdr;
	s32			result;
	u32			clt_device_id;
	u32			device_id;
	u32			max_hw_sectors;
	u32			max_write_same_sectors;
	u32			max_discard_sectors;
	u32			discard_zeroes_data;
	u32			discard_granularity;
	u32			discard_alignment;
	u16			physical_block_size;
	u16			logical_block_size;
	u16			max_segments;
	u16			secure_discard;
	u64			nsectors;
	u8			rotational;
	u8			io_mode;
	u8			__padding[6];
};

/**
 * enum ibnbd_io_flags - IBNBD request types from rq_flag_bits
 * @IBNBD_RW_REQ_WRITE:	bit not set = read, bit set = write
 * @IBNBD_RW_REQ_SYNC:	request is sync
 * @IBNBD_RW_REQ_DISCARD: request to discard sectors
 * @IBNBD_RW_REQ_SECURE: secure discard request
 * @IBNBD_RW_REQ_WRITE_SAME: write same block many times
 */
enum ibnbd_io_flags {
	IBNBD_RW_REQ_WRITE		= 1 << 1,
	IBNBD_RW_REQ_SYNC		= 1 << 2,
	IBNBD_RW_REQ_DISCARD		= 1 << 3,
	IBNBD_RW_REQ_SECURE		= 1 << 4,
	IBNBD_RW_REQ_WRITE_SAME		= 1 << 5,
	IBNBD_RW_REQ_FUA		= 1 << 6,
	IBNBD_RW_REQ_FLUSH		= 1 << 7
};

/**
 * struct ibnbd_msg_revalidate - notify client about new device size
 * @hdr:		message header
 * @clt_device_id:	device_id on client side
 * @nsectors:		number of sectors
 */
struct ibnbd_msg_revalidate {
	struct ibnbd_msg_hdr	hdr;
	u32			clt_device_id;
	u64			nsectors;
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
	u32		device_id;
	u64		sector;
	u32		rw;
	u32		bi_size;
};

#if GCC_DIAGNOSTIC_AWARE
#pragma GCC diagnostic pop
#endif

int ibnbd_validate_message(const void *data, size_t len);
const char *ibnbd_io_mode_str(enum ibnbd_io_mode mode);
const char *ibnbd_access_mode_str(enum ibnbd_access_mode mode);

#endif /* __IBNBD_PROTO_H */
