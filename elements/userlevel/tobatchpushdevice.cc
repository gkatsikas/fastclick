/*
 * tobatchpushdevice.{cc,hh} -- element writes packets to network via pcap library
 * Douglas S. J. De Couto, Eddie Kohler, John Jannotti
 *
 * Transformed into a full push element with computational batching support
 * by Georgios Katsikas
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2005-2008 Regents of the University of California
 * Copyright (c) 2011 Meraki, Inc.
 * Copyright (c) 2016 KTH Royal Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>

#include "tobatchpushdevice.hh"
#include <click/error.hh>
#include <click/etheraddress.hh>
#include <click/args.hh>
#include <click/router.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <stdio.h>
#include <unistd.h>

# include <sys/socket.h>
# include <sys/ioctl.h>
# include <net/if.h>
# include <net/if_packet.h>
# include <features.h>
# if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
#  include <netpacket/packet.h>
# else
#  include <linux/if_packet.h>
# endif

CLICK_DECLS

#if HAVE_BATCH
// Maximum number of packets (or batch size) this element can pull from its predecessor
static const short PULL_LIMIT = 256;
// The size of the buffer is set to the standard MTU.
// If the application handles small packets, syscall overhead will be substantially amortized.
static const short BATCH_BUFFER_SIZE = 1514;
#endif

ToBatchPushDevice::ToBatchPushDevice() : _q(0), _emitted(0), _fd(-1), _my_fd(false)
{
}

ToBatchPushDevice::~ToBatchPushDevice()
{
}

int
ToBatchPushDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String method;
    _burst = 1;
    if (Args(conf, this, errh)
	.read_mp("DEVNAME", _ifname)
	.read("DEBUG", _debug)
	.read("METHOD", WordArg(), method)
	.read("BURST", _burst)
	.complete() < 0)
	return -1;

    if (!_ifname)
	return errh->error("interface not set");

    if (_burst <= 0)
	return errh->error("bad BURST");

#if HAVE_BATCH
	if (batch_mode() == BATCH_MODE_YES)
		errh->warning("BURST is unused with batching!");
#endif

    if (method == "") {
	_method = method_linux;
    }
    else if (method == "LINUX")
	_method = method_linux;
    else
	return errh->error("bad METHOD");

    return 0;
}

FromBatchDevice *
ToBatchPushDevice::find_fromdevice() const
{
    Router *r = router();
    for (int ei = 0; ei < r->nelements(); ++ei) {
	FromBatchDevice *fd = (FromBatchDevice *) r->element(ei)->cast("FromBatchDevice");
	if (fd && fd->ifname() == _ifname && fd->fd() >= 0)
	    return fd;
    }
    return 0;
}

int
ToBatchPushDevice::initialize(ErrorHandler *errh)
{
    FromBatchDevice *fd = find_fromdevice();
    if (fd && _method == method_default) {
	if (fd->fd() >= 0)
	    _method = method_linux;
    }

    if (fd && fd->fd() >= 0)
	_fd = fd->fd();
    else {
	_fd = FromBatchDevice::open_packet_socket(_ifname, errh);
	if (_fd < 0)
		return -1;
	_my_fd = true;
    }

    // check for duplicate writers
    void *&used = router()->force_attachment("device_writer_" + _ifname);
    if (used)
	return errh->error("duplicate writer for device %<%s%>", _ifname.c_str());
    used = this;

    return 0;
}

void
ToBatchPushDevice::cleanup(CleanupStage)
{
    if (_fd >= 0 && _my_fd)
	close(_fd);
    _fd = -1;
}


/*
 * Linux select marks datagram fd's as writeable when the socket
 * buffer has enough space to do a send (sock_writeable() in
 * sock.h). BSD select always marks datagram fd's as writeable
 * (bpf_poll() in sys/net/bpf.c) This function should behave
 * appropriately under both.  It makes use of select if it correctly
 * tells us when buffers are available, and it schedules a backoff
 * timer if buffers are not available.
 * --jbicket
 */
int
ToBatchPushDevice::send_packet(Packet *p)
{
    int r = 0;
    errno = 0;

    r = send(_fd, p->data(), p->length(), 0);
    if (r >= 0)
	return 0;
    return errno ? -errno : -EINVAL;
}

#if HAVE_BATCH
int
ToBatchPushDevice::emit_batch(unsigned char *batch_data, unsigned short batch_len) {
	return send(_fd, &batch_data[0], batch_len, 0);
}

int
ToBatchPushDevice::send_batch(PacketBatch *batch) {
	int r        = 0;
	int count    = 0;
	int syscalls = 0;

	Packet *current = batch;
	unsigned int buffer_size = BATCH_BUFFER_SIZE;

	// Fixed-length buffer that hosts packets to be emitted.
	unsigned char batch_data[buffer_size];
	memset(batch_data, 0, buffer_size*sizeof(unsigned char));
	unsigned int buf_index = 0;
	bool emitted = false;

	// Iterate the batch
	while ( current ) {
		Packet *next = current->next();

		//click_chatter("Curr: %d  -  Available size: %d)", current->length(), (buffer_size - buf_index));

		// Not enough space for this packet
		if ( current->length() > (buffer_size - (buf_index)) ) {
			// Emit the buffer and reset it to host this new packet
			int bytes_sent = emit_batch(batch_data, buf_index);
			if ( (bytes_sent >= 0) && (bytes_sent == buf_index) ) {
				r += bytes_sent;
				emitted = true;
				syscalls ++;
			}
			else {
				click_chatter("[ERROR] [IN LOOP] Failed to emit batch");
				return 0;
			}

			memset(&batch_data[0], 0, buffer_size*sizeof(unsigned char));
			buf_index = 0;
		}

		// Keep this packet in the buffer
		if ( (buf_index + current->length()) <= buffer_size ) {
			memcpy(&batch_data[buf_index], current->data(), current->length());
			buf_index += current->length();
			emitted = false;
		}
		else {
			click_chatter("[ERROR] Attempted to write more bytes than the available buffer size");
			return 0;
		}

		current->set_next(next);
		current  = next;
		count++;
	}

	// Leftovers will be emitted now
	if ( ! emitted ) {
		int bytes_sent = emit_batch(&batch_data[0], buf_index);
		if ( (bytes_sent >= 0) && (bytes_sent == buf_index) ) {
			r += bytes_sent;
			syscalls ++;
		}
		else if ( (bytes_sent >= 0) && (bytes_sent < buf_index) ) {
			bytes_sent = emit_batch(&batch_data[bytes_sent-1], buf_index-bytes_sent);
			if ( bytes_sent != buf_index-bytes_sent ) {
				click_chatter("[ERROR] [OUT OF LOOP] Failed to emit batch");
			}
			r += bytes_sent;
		}
		else {
			click_chatter("[ERROR] [OUT OF LOOP] Failed to emit batch");
			return 0;
		}
	}

	// Upon success, returns the number of packets sent
	if (r >= 0) {
		//click_chatter("Transmitted packets %d (%d bytes) with %d syscalls", count, r, syscalls);
		return count;
	}
	return 0;
}
#endif

void
ToBatchPushDevice::push_packet(int, Packet *p)
{
	int count = 0;

	do {
		if ( send_packet(p) >= 0 ) {
			++count;
			++_emitted;
		}
		else
			break;
	} while (count < _burst);
}

#if HAVE_BATCH
void
ToBatchPushDevice::push_batch(int, PacketBatch *batch)
{
	_emitted += send_batch(batch);
}
#endif

String
ToBatchPushDevice::read_param(Element *e, void *thunk)
{
    ToBatchPushDevice *td = static_cast<ToBatchPushDevice *>(e);
    switch((uintptr_t) thunk) {
    case h_debug:
	return String(td->_debug);
    case h_q:
	return String((bool) td->_q);
    case h_emitted:
	return String(td->_emitted);
    default:
	return String();
    }
}

int
ToBatchPushDevice::write_param(const String &in_s, Element *e, void *vparam,
		     ErrorHandler *errh)
{
    ToBatchPushDevice *td = static_cast<ToBatchPushDevice *>(e);
    String s = cp_uncomment(in_s);
    switch ((intptr_t)vparam) {
	case h_debug: {
		bool debug;
		if (!BoolArg().parse(s, debug))
			return errh->error("type mismatch");
		td->_debug = debug;
		break;
	}
    }
    return 0;
}

void
ToBatchPushDevice::add_handlers()
{
    add_read_handler("debug", read_param, h_debug, Handler::CHECKBOX);
    add_read_handler("q", read_param, h_q);
    add_read_handler("emitted", read_param, h_emitted);
    add_write_handler("debug", write_param, h_debug);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(FromBatchDevice userlevel)
EXPORT_ELEMENT(ToBatchPushDevice)
