/*
 * todevice.{cc,hh} -- element writes packets to network via pcap library
 * Douglas S. J. De Couto, Eddie Kohler, John Jannotti
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2005-2008 Regents of the University of California
 * Copyright (c) 2011 Meraki, Inc.
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
#include <click/args.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>

#include "tommapdevice.hh"

CLICK_DECLS

ToMMapDevice::ToMMapDevice() :
	_task(this), _n_sent(0), _n_dropped(0), _ring(0),
	_fd(-1), _timeout(0), _blocking(false),
	_burst_size(32), _congestion_warning_printed(false),
	_internal_tx_queue_size(-1), _verbose(false), _debug(false)
{
}

ToMMapDevice::~ToMMapDevice()
{
	if ( _verbose && _debug )
		click_chatter("[%s] Sent: %7d packets", _ifname.c_str(), _n_sent);
}

int
ToMMapDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if (Args(conf, this, errh)
			.read_mp("DEVNAME",  _ifname)
			.read   ("IQUEUE",   _internal_tx_queue_size)
			.read   ("BURST",    _burst_size)
			.read   ("BLOCKING", _blocking)
			.read   ("TIMEOUT",  _timeout)
			.read   ("VERBOSE",  _verbose)
			.read   ("DEBUG",    _debug)
			.complete() < 0)
		return -1;

	if ( !_ifname )
		return errh->error("[%s] Interface not set", name().c_str());

	if ( _burst_size <= 0 )
		return errh->error("[%s] [%s] Bad BURST", name().c_str(), _ifname.c_str());

	if ( _internal_tx_queue_size <= 0 ) {
		_internal_tx_queue_size = 1024;
		errh->warning("[%s] [%s] Non-positive IQUEUE size. Setting default (%d)",
					name().c_str(), _ifname.c_str(), _internal_tx_queue_size);
	}

	return 0;
}

FromMMapDevice *
ToMMapDevice::find_fromdevice() const
{
	Router *r = router();
	for (int ei = 0; ei < r->nelements(); ++ei) {
		FromMMapDevice *fd = (FromMMapDevice *) r->element(ei)->cast("FromMMapDevice");
		if (fd && fd->ifname() == _ifname && fd->fd() >= 0)
			return fd;
	}
	return 0;
}

int
ToMMapDevice::initialize(ErrorHandler *errh)
{
	if ( !_ifname )
		return errh->error("ToMMapDevice: Interface not set");

	// Get debugging information from the library
	MMapDevice::set_debug_info(_verbose, _debug);

	int ret = MMapDevice::add_tx_device(_ifname, _burst_size);
	if (ret != 0)
		return ret;

	FromMMapDevice *fd = find_fromdevice();
	_ring = fd->get_fromdevice_mmap(_ifname, errh);

	bool existed = false;
	_fd = fd->get_fromdevice_fd(_ifname, &existed, errh);

	// Check for duplicate writers
	void *&used = router()->force_attachment("device_writer_" + _ifname);
	if ( used )
		return errh->error("[%s] [%s] Duplicate writer for this device", name().c_str(), _ifname.c_str());
	used = this;

	ret = MMapDevice::setup_poll(_ifname, _ring, TX_MODE);
	if ( ret != 0 )
		return ret;

	// Allocate space for the internal queue
	_iqueue.pkts = new Packet *[_internal_tx_queue_size];
	if (_timeout >= 0) {
		_iqueue.timeout.assign(this);
		_iqueue.timeout.initialize(this);
		_iqueue.timeout.move_thread(click_current_cpu_id());
	}
	//click_chatter("[%s] [%s] Internal queue allocated %d packet buffers",
	//			name().c_str(), _ifname.c_str(), _internal_tx_queue_size);

	ScheduleInfo::initialize_task(this, &_task, false, errh);

	return 0;
}

void
ToMMapDevice::cleanup(CleanupStage)
{
	if ( _iqueue.pkts )
		delete[] _iqueue.pkts;
}

int
ToMMapDevice::send_packet(Packet *p)
{
	return MMapDevice::walk_tx_ring_packet(_ifname, _ring, p);
}

#if HAVE_BATCH
int
ToMMapDevice::send_batch(PacketBatch *batch)
{
	return MMapDevice::walk_tx_ring_batch(_ifname, _ring, batch);
}
#endif

void
ToMMapDevice::set_flush_timer(TXInternalQueue &iqueue)
{
	if ( _timeout >= 0 ) {
		if ( iqueue.timeout.scheduled() ) {
			// No more pending packets, remove timer
			if ( iqueue.nr_pending == 0 )
				iqueue.timeout.unschedule();
		}
		else {
			if ( iqueue.nr_pending > 0 )
				// Pending packets, set timeout to flush packets
				// after a while even without burst
				if ( _timeout == 0 )
					iqueue.timeout.schedule_now();
				else
					iqueue.timeout.schedule_after_msec(_timeout);
		}
	}
}

/*
 * Flush as many packets as possible from the internal queue
 */
void
ToMMapDevice::flush_internal_tx_queue(TXInternalQueue &iqueue)
{
	unsigned short sent = 0;

	do {
		if ( send_packet(iqueue.pkts[iqueue.index]) < 0 ) {
			if ( _verbose ) {
				click_chatter("[%s] [%s] Failed to emit packet",
					name().c_str(), _ifname.c_str());
			}
			break;
		}

		++sent;

		iqueue.nr_pending --;
		iqueue.index      ++;

		// Wrapping around the ring
		if (iqueue.index >= _internal_tx_queue_size)
			iqueue.index = 0;

	} while ( iqueue.nr_pending > 0 );

	_n_sent += sent;

	// If ring is empty, reset the index to avoid wrap ups
	if ( iqueue.nr_pending == 0 )
		iqueue.index = 0;
}

#if HAVE_BATCH
void
ToMMapDevice::flush_internal_tx_queue_batch(TXInternalQueue &iqueue)
{
	int pkts_in_batch = 0;

	PacketBatch    *head = NULL;
	WritablePacket *last = NULL;

	do {
		if ( !head )
			head = PacketBatch::start_head(iqueue.pkts[iqueue.index]);
		else
			last->set_next(iqueue.pkts[iqueue.index]);
		last = (WritablePacket *) iqueue.pkts[iqueue.index];

		iqueue.nr_pending --;
		iqueue.index      ++;

		// Wrapping around the ring
		if (iqueue.index >= _internal_tx_queue_size)
			iqueue.index = 0;

		++pkts_in_batch;

	} while ( (iqueue.nr_pending > 0) && (pkts_in_batch < _burst_size) );

	if ( !head || (pkts_in_batch <= 0) )
		return;

	// Assimilate the batch
	head->make_tail(last, pkts_in_batch);

	// Transmit the batch
	int sent = send_batch(head);

	// Problem occured
	if ( sent < 0 ) {
		if ( _verbose )
			click_chatter("[%s] [%s] Failed to emit batch with %d packets",
				name().c_str(), _ifname.c_str(), pkts_in_batch);
		return;
	}
	//click_chatter("[%s] [%s] Sent: %2d packets", name().c_str(), _ifname.c_str(), sent);

	_n_sent += sent;

	// If ring is empty, reset the index to avoid wrap ups
	if ( iqueue.nr_pending == 0 )
		iqueue.index = 0;
}
#endif

void
ToMMapDevice::push_packet(int port, Packet *p)
{
	if ( !p )
		return;

	// Get the internal queue
	TXInternalQueue &iqueue = _iqueue;

	bool congestioned;

	do {
		congestioned = false;

		// Internal queue is full
		if ( iqueue.nr_pending == _internal_tx_queue_size ) {
			// We just set the congestion flag. If we're in blocking mode,
			// we'll loop, else we'll drop this packet.
			congestioned = true;

			if ( !_blocking ) {
				++_n_dropped;

				if ( !_congestion_warning_printed )
					click_chatter("[%s] [%s] Packet dropped", name().c_str(), _ifname.c_str());
				_congestion_warning_printed = true;
			}
			else {
				if ( !_congestion_warning_printed )
					click_chatter("[%s] [%s] Congestion warning", name().c_str(), _ifname.c_str());
				_congestion_warning_printed = true;
			}
		}
		// There is space in the iqueue
		else {
			iqueue.pkts[(iqueue.index + iqueue.nr_pending) % _internal_tx_queue_size] = p;
			iqueue.nr_pending++;
		}

		if ( ((int) iqueue.nr_pending > 0) || congestioned ) {
			flush_internal_tx_queue(iqueue);
		}
		// We wait until burst for sending packets, so flushing timer is especially important here
		set_flush_timer(iqueue);

		// If we're in blocking mode, we loop until we can put p in the iqueue
	} while ( unlikely(_blocking && congestioned) );

	// Time to kill
	if ( likely(is_fullpush()) ) {
		p->safe_kill();
	}
	else {
		p->kill();
	}
}

#if HAVE_BATCH
void ToMMapDevice::push_batch(int, PacketBatch *head)
{
	// Get the internal queue
	TXInternalQueue &iqueue = _iqueue;

	Packet *p    = head;
	Packet *next = NULL;

	BATCH_RECYCLE_START();

	bool congestioned;

	do {
		congestioned = false;

		// First, place the packets in the queue, while there is still place there
		while ( iqueue.nr_pending < _internal_tx_queue_size && p ) {

			if ( p ) {
				iqueue.pkts[(iqueue.index + iqueue.nr_pending) % _internal_tx_queue_size] = p;
				iqueue.nr_pending++;
			}
			next = p->next();

			BATCH_RECYCLE_UNSAFE_PACKET(p);

			p = next;
		}

		// There are packets not pushed into the queue, congestion is very likely!
		if ( p ) {
			congestioned = true;
			if ( !_congestion_warning_printed ) {
				if ( !_blocking )
					click_chatter("[%s] Packet dropped", name().c_str());
				else
					click_chatter("[%s] Congestion warning", name().c_str());
				_congestion_warning_printed = true;
			}
		}

		// Flush the queue if we have pending packets
		if ( ((int) iqueue.nr_pending > 0) || congestioned ) {
			flush_internal_tx_queue_batch(iqueue);
		}
		set_flush_timer(iqueue);

		// If we're in blocking mode, we loop until we can put p in the iqueue
	} while ( unlikely(_blocking && congestioned) );

	// If non-blocking, drop all packets that could not be sent
	while ( p ) {
		next = p->next();
		BATCH_RECYCLE_UNSAFE_PACKET(p);
		p = next;
		++_n_dropped;
	}

	BATCH_RECYCLE_END();
}
#endif

String
ToMMapDevice::read_handler(Element *e, void *thunk)
{
	ToMMapDevice *td = static_cast<ToMMapDevice *>(e);

	switch((uintptr_t) thunk) {
		case h_sent:
			return String(td->_n_sent);
		case h_dropped:
			return String((bool) td->_n_dropped);
	}
}

void
ToMMapDevice::add_handlers()
{
	add_read_handler ("sent",    read_handler, h_sent);
	add_read_handler ("dropped", read_handler, h_dropped);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(FromMMapDevice userlevel)
EXPORT_ELEMENT(ToMMapDevice)
