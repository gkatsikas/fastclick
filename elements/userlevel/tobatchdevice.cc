/*
 * tobatchdevice.{cc,hh} -- element writes packets to Linux-based interfaces
 * Douglas S. J. De Couto, Eddie Kohler, John Jannotti
 *
 * Transformed into a full push element with an internal queue that supports
 * both normal and batch push.
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
#include <click/error.hh>
#include <click/args.hh>
#include <click/standard/scheduleinfo.hh>

#include "tobatchdevice.hh"

CLICK_DECLS

ToBatchDevice::ToBatchDevice()
	: 	_task(this), _n_sent(0), _n_dropped(0),
		_fd(-1), _my_fd(false),	_timeout(0), _blocking(false),
		_congestion_warning_printed(false), 
		_internal_tx_queue_size(-1), _from_dev_core(0)
{
}

ToBatchDevice::~ToBatchDevice()
{
}

int
ToBatchDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
	String method;
	_burst_size = 1;

	if (Args(conf, this, errh)
			.read_mp("DEVNAME", _ifname)
			.read("BURST",      _burst_size)
			.read("IQUEUE",     _internal_tx_queue_size)
			.read("BLOCKING",   _blocking)
			.read("TIMEOUT",    _timeout)
			.complete() < 0)
		return -1;

	if ( !_ifname )
		return errh->error("[%s] Interface not set", name().c_str());

	if ( _burst_size <= 0 )
		return errh->error("[%s] Bad BURST", name().c_str());

	if ( _internal_tx_queue_size == 0 ) {
		_internal_tx_queue_size = 1024;
		errh->warning("[%s] Non-positive IQUEUE size. Setting default (%d) \n",
					name().c_str(), _internal_tx_queue_size);
	}

#if HAVE_BATCH
	if ( batch_mode() == BATCH_MODE_YES )
		errh->warning("[%s] BURST is unused with batching!", name().c_str());
#endif

	return 0;
}

FromBatchDevice *
ToBatchDevice::find_fromdevice() const
{
	Router *r = router();
	for (int ei = 0; ei < r->nelements(); ++ei) {
		FromBatchDevice *fd = (FromBatchDevice *) r->element(ei)->cast("FromBatchDevice");
		if (fd && fd->ifname() == _ifname && fd->fd() >= 0) {
			return fd;
		}
	}
	return 0;
}

int
ToBatchDevice::find_fromdevice_core() const
{
	Router *r = router();
	for (int ei = 0; ei < r->nelements(); ++ei) {
		FromBatchDevice *fd = (FromBatchDevice *) r->element(ei)->cast("FromBatchDevice");
		if (fd && fd->ifname() == _ifname && fd->fd() >= 0) {
			return router()->home_thread_id(fd);
		}
	}
	return -1;
}

int
ToBatchDevice::initialize(ErrorHandler *errh)
{
	//_timer.initialize(this);

	FromBatchDevice *fd = find_fromdevice();

	if (fd && fd->fd() >= 0)
		_fd = fd->fd();
	else {
		_fd = FromBatchDevice::open_packet_socket(_ifname, errh);

		if (_fd < 0)
			return -1;
		_my_fd = true;
	}

	// Check for duplicate writers
	void *&used = router()->force_attachment("device_writer_" + _ifname);
	if (used)
		return errh->error("[%s] Duplicate writer for device: %s", name().c_str(), _ifname.c_str());
	used = this;

	// Allocate space for the internal queue
	_iqueue.pkts = new Packet *[_internal_tx_queue_size];
	if (_timeout >= 0) {
		_iqueue.timeout.assign(this);
		_iqueue.timeout.initialize(this);
		_iqueue.timeout.move_thread(click_current_cpu_id());
	}

	ScheduleInfo::initialize_task(this, &_task, false, errh);

//	ScheduleInfo::join_scheduler(this, &_task, errh);
//	_signal = Notifier::upstream_empty_signal(this, 0, &_task);

//	click_chatter("  ToBatchDevice[%s] has CPU ID %d", _ifname.c_str(), router()->home_thread_id(this));
//	click_chatter("FromBatchDevice[%s] has CPU ID %d", _ifname.c_str(), find_fromdevice_core());

	return 0;
}

void
ToBatchDevice::cleanup(CleanupStage)
{
	if (_fd >= 0 && _my_fd)
		close(_fd);
	_fd = -1;

	if ( _iqueue.pkts )
		delete[] _iqueue.pkts;
}

int
ToBatchDevice::send_packet(Packet *p)
{
	if ( !p || p->length() == 0 )
		return -EINVAL;

	int r = 0;
	errno = 0;

	r = send(_fd, p->data(), p->length(), 0);

	if (r >= 0)
		return 0;
	return errno ? -errno : -EINVAL;
}

inline void
ToBatchDevice::set_flush_timer(TXInternalQueue &iqueue)
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

/* Flush as many packets as possible from the internal queue of the DPDK ring. */
void
ToBatchDevice::flush_internal_tx_queue(TXInternalQueue &iqueue)
{
	unsigned short sent = 0;

	do {
		if ( send_packet(iqueue.pkts[iqueue.index]) < 0 )
			break;

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

void
ToBatchDevice::push_packet(int, Packet *p)
{
//	click_chatter("ToBatchDevice[%s] from CPU: %d",	_ifname.c_str(), router()->home_thread_id(this));

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
					click_chatter("[%s] Packet dropped", name().c_str());
				_congestion_warning_printed = true;
			}
			else {
				if ( !_congestion_warning_printed )
					click_chatter("[%s] Congestion warning", name().c_str());
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
void
ToBatchDevice::push_batch(int, PacketBatch *head)
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

			if ( p != NULL ) {
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
			flush_internal_tx_queue(iqueue);
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
ToBatchDevice::read_handler(Element *e, void *thunk)
{
	ToBatchDevice *td = static_cast<ToBatchDevice*>(e);

	if ( thunk == (void *) 0 )
		return String(td->_n_sent);
	else
		return String(td->_n_dropped);
}

void
ToBatchDevice::add_handlers()
{
	add_read_handler("n_sent",    read_handler, 0);
	add_read_handler("n_dropped", read_handler, 1);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(FromBatchDevice userlevel)
EXPORT_ELEMENT(ToBatchDevice)
