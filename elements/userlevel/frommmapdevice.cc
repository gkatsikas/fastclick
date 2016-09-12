// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * frommmapdevice.{cc,hh} -- element reads packets live from network packet mmap.
 * Uses computational batching as per the Fast-Click model.
 * Georgios Katsikas
 *
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
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/args.hh>

#include "frommmapdevice.hh"

CLICK_DECLS

FromMMapDevice::FromMMapDevice() :
	_n_recv(0), _burst_size(32), _verbose(false), _debug(false)
{
#if HAVE_BATCH
	in_batch_mode = BATCH_MODE_YES;
#endif
}

FromMMapDevice::~FromMMapDevice()
{
	if ( _verbose && _debug )
		click_chatter("[%s] Read: %7d packets", _ifname.c_str(), _n_recv);
}

int
FromMMapDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (Args(conf, this, errh)
		.read_mp("DEVNAME", _ifname)
		.read   ("BURST",   _burst_size)
		.read   ("VERBOSE", _verbose)
		.read   ("DEBUG",   _debug)
		.complete() < 0)
		return -1;

	if ( _burst_size <= 0 )
		return errh->error("[%s] [%s] BURST out of range", name().c_str(), _ifname.c_str());

	return 0;
}

int
FromMMapDevice::initialize(ErrorHandler *errh)
{
	if ( !_ifname )
		return errh->error("FromMMapDevice: Interface not set");

	// Get debugging information from the library
	MMapDevice::set_debug_info(_verbose, _debug);

	// TODO: Multiple queues?
	int ret = MMapDevice::add_rx_device(_ifname, _burst_size);
	if ( ret != 0 )
		return ret;

	ret = MMapDevice::initialize(errh);
	if ( ret != 0 )
		return ret;

	_ring = MMapDevice::get_ring(_ifname);

	int fd = -1;
	if ( !_ring ) {
		fd = setup_device(_ifname, &_ring, errh);
	}
	else {
		fd = _ring->sock_fd;
	}

	ret = MMapDevice::setup_poll(_ifname, _ring, RX_MODE);
	if ( ret != 0 )
		return ret;

	if (KernelFilter::device_filter(_ifname, true, errh) < 0)
		errh->warning("[%s] Failed to setup kernel filter", _ifname.c_str());

	add_select(fd, SELECT_READ);

	return 0;
}

void
FromMMapDevice::cleanup(CleanupStage stage)
{
	if ( stage >= CLEANUP_INITIALIZED )
		KernelFilter::device_filter(_ifname, false, ErrorHandler::default_handler());

	if ( _ring ) {
		if ( MMapDevice::unmap_ring(_ifname) != 0 ) {
			return;
		}
		if ( _ring->sock_fd >= 0 )
			remove_select(_ring->sock_fd, SELECT_READ);
	}
}

int
FromMMapDevice::setup_device(const String ifname, struct ring **ring, ErrorHandler *errh)
{
	// Supported versions are TPACKET_V1, TPACKET_V2
	int version = TPACKET_V2;

	*ring = MMapDevice::alloc_ring(ifname);
	if ( ! *ring ) {
		return errh->error("[%s] Cannot allocate memory", ifname.c_str());
	}

	// Open the socket
	int fd = MMapDevice::open_socket(ifname, *ring, version);
	if ( fd < 0 ) {
		return errh->error("[%s] Bad file descriptor", ifname.c_str());
	}

	// Setup ring buffer
	int ret = MMapDevice::setup_ring(ifname, *ring, version);
	if ( ret != 0 ) {
		return errh->error("[%s] Failed to setup ring buffers", ifname.c_str());
	}

	// Map memory
	ret = MMapDevice::mmap_ring(ifname, *ring);
	if ( ret != 0 ) {
		return errh->error("[%s] Failed to map memory", ifname.c_str());
	}

	// Bind socket
	ret = MMapDevice::bind_ring(ifname, *ring);
	if ( ret != 0 ) {
		return errh->error("[%s] Ring bind", ifname.c_str());
	}

	return fd;
}

void
FromMMapDevice::selected(int, int)
{
#if HAVE_BATCH
	PacketBatch *batch = MMapDevice::walk_rx_ring_batch(_ifname, _ring);
	if ( !batch ) {
		click_chatter("[%s] [%s] [Receive] Invalid batch", name().c_str(), _ifname.c_str());
		return;
	}
	output_push_batch(0, batch);
	_n_recv += batch->count();
#else
	Packet *packet = MMapDevice::walk_rx_ring_packet(_ifname, _ring);
	if ( !packet ) {
		click_chatter("[%s] [%s] [Receive] Invalid packet", name().c_str(), _ifname.c_str());
		packet->kill();
		return;
	}
	output(0).push(packet);
	++_n_recv;
#endif
}

String
FromMMapDevice::read_handler(Element *e, void *thunk)
{
	FromMMapDevice *fd = static_cast<FromMMapDevice *>(e);

	if ( thunk == (void *) 0 )
		return String(fd->_n_recv);
}

int
FromMMapDevice::write_handler(const String &, Element *e, void *, ErrorHandler *)
{
	FromMMapDevice *fd = static_cast<FromMMapDevice *>(e);
	fd->_n_recv     = 0;
	return 0;
}

void
FromMMapDevice::add_handlers()
{
	add_read_handler ("count",        read_handler,  0);
	add_write_handler("reset_counts", write_handler, 0, Handler::BUTTON);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel KernelFilter)
EXPORT_ELEMENT(FromMMapDevice)
ELEMENT_MT_SAFE(FromMMapDevice)
