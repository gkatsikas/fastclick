/*
 * tobatchdevice.{cc,hh} -- element writes packets to Linux-based interfaces
 * Douglas S. J. De Couto, Eddie Kohler, John Jannotti
 *
 * Transformed into a full push element with an internal queue that supports
 * both normal and batch push operations as well as bathcing of system calls.
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

ToBatchDevice::ToBatchDevice() :
	_task(this), _n_sent(0), _n_dropped(0),
	_fd(-1), _my_fd(false),	_timeout(0), _blocking(false),
	_congestion_warning_printed(false), _verbose(false),
	_internal_tx_queue_size(-1)
{
#if HAVE_BATCH
	_msgs   = 0;
	_iovecs = 0;
#endif
}

ToBatchDevice::~ToBatchDevice()
{
	if (_verbose) {
		click_chatter(
			"\n[%s] [%s] Sent: %" PRIu64 " - Dropped: %" PRIu64 "",
			name().c_str(), _ifname.c_str(), _n_sent, _n_dropped
		);
	}
}

int
ToBatchDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
	String method;
	_burst_size = BATCHDEV_DEF_PREF_BATCH_SIZE;

	if (Args(conf, this, errh)
			.read_mp("DEVNAME",  _ifname)
			.read   ("BURST",    _burst_size)
			.read   ("IQUEUE",   _internal_tx_queue_size)
			.read   ("BLOCKING", _blocking)
			.read   ("TIMEOUT",  _timeout)
			.read   ("VERBOSE",  _verbose)
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

#if HAVE_BATCH
	if ( _verbose )
		click_chatter("[%s] [%s] Tx will batch up to BURST (%d) packets",
				name().c_str(), _ifname.c_str(), _burst_size);

	if ( (_burst_size < BATCHDEV_MIN_PREF_BATCH_SIZE) || (_burst_size > BATCHDEV_MAX_PREF_BATCH_SIZE) )
		errh->warning("[%s] [%s] To improve the I/O performance set a BURST value in [%d-%d], preferably %d.",
				name().c_str(), _ifname.c_str(), BATCHDEV_MIN_PREF_BATCH_SIZE, BATCHDEV_MAX_PREF_BATCH_SIZE,
				BATCHDEV_DEF_PREF_BATCH_SIZE);
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

#if HAVE_BATCH
	// Pre-allocate memory for '_burst_size' packets
	_msgs = (struct mmsghdr *)  malloc(_burst_size * sizeof(struct mmsghdr));
	if ( !_msgs )
		return errh->error("[%s] [%s] Cannot pre-allocate message buffers",
			name().c_str(), _ifname.c_str());
	memset(_msgs, 0, _burst_size * sizeof(struct mmsghdr));

	// Pre-allocate memory for '_burst_size' packets
	_iovecs = (struct iovec *)  malloc(_burst_size * sizeof(struct iovec));
	if ( !_iovecs )
		return errh->error("[%s] [%s] Cannot pre-allocate ring buffers",
			name().c_str(), _ifname.c_str());
	memset(_iovecs, 0, _burst_size * sizeof(struct iovec));

	for (unsigned short i = 0; i < _burst_size; i++) {
		// Message structure understood by the recvmmsg syscall
		_msgs  [i].msg_hdr.msg_iov    = &_iovecs[i];
		_msgs  [i].msg_hdr.msg_iovlen = 1;
	}
#endif

	ScheduleInfo::initialize_task(this, &_task, false, errh);

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

#if HAVE_BATCH
	if ( _msgs )
		free(_msgs);
	if ( _iovecs )
		free(_iovecs);
#endif
}

int
ToBatchDevice::send_packet(Packet *p)
{
	if ( !p || p->length() == 0 )
		return -EINVAL;

	errno = 0;

	int r = send(_fd, p->data(), p->length(), 0);

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

/*
 * Flush as many packets as possible from the internal queue of the DPDK ring
 */
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

#if HAVE_BATCH
void
ToBatchDevice::flush_internal_tx_queue_batch(TXInternalQueue &iqueue)
{
	unsigned pkts_in_batch = 0;

	do {
		// Add this packet to the vector ring
		_iovecs[pkts_in_batch].iov_base = (void *) iqueue.pkts[iqueue.index]->data();
		_iovecs[pkts_in_batch].iov_len  = iqueue.pkts[iqueue.index]->length();
		//_msgs  [pkts_in_batch].msg_hdr.msg_iov    = &_iovecs[pkts_in_batch];
		//_msgs  [pkts_in_batch].msg_hdr.msg_iovlen = 1;

		iqueue.nr_pending --;
		iqueue.index      ++;

		// Wrapping around the ring
		if ( iqueue.index >= _internal_tx_queue_size )
			iqueue.index = 0;

		++pkts_in_batch;

	} while ( (iqueue.nr_pending > 0) && (pkts_in_batch < _burst_size) );

	// Transmit the batch
	int sent = sendmmsg(_fd, _msgs, pkts_in_batch, 0);

	// Problem occured
	if ( sent == -1 ) {
		/*if ( _verbose ) {
			click_chatter("[%s] [%s] Failed to emit batch with %d packets",
				name().c_str(), _ifname.c_str(), pkts_in_batch);
		}*/
		return;
	}
	else if ( sent < pkts_in_batch ) {
		//click_chatter("[%s] [%s] Sent %d/%d packets",
		//		name().c_str(), _ifname.c_str(), sent, pkts_in_batch);
		//sent += sendmmsg(_fd, &_msgs[sent], pkts_in_batch-sent, 0);
	}
	//click_chatter("[%s] [%s] Sent: %2d/%2d packets", name().c_str(), _ifname.c_str(), sent, pkts_in_batch);

	_n_sent += sent;

	// If ring is empty, reset the index to avoid wrap ups
	if ( iqueue.nr_pending == 0 )
		iqueue.index = 0;

	// Clean the memory for the next batch
	//memset(_msgs,   0, _burst_size * sizeof(struct mmsghdr));
	//memset(_iovecs, 0, _burst_size * sizeof(struct iovec));
}
#endif

void
ToBatchDevice::push(int, Packet *p)
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
		p->kill_nonatomic();
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

			if ( p ) {
				iqueue.pkts[(iqueue.index + iqueue.nr_pending) % _internal_tx_queue_size] = p;
				iqueue.nr_pending++;
			}
			next = p->next();

			BATCH_RECYCLE_PACKET_CONTEXT(p);

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
		BATCH_RECYCLE_PACKET_CONTEXT(p);
		p = next;
		++_n_dropped;
	}

	BATCH_RECYCLE_END();
}
#endif

String
ToBatchDevice::read_handler(Element *e, void *thunk)
{
	ToBatchDevice *td = static_cast<ToBatchDevice *>(e);

	switch((uintptr_t) thunk) {
		case h_sent:
			return String(td->_n_sent);
		case h_dropped:
			return String((bool) td->_n_dropped);
		default:
			break;
	}
}

void
ToBatchDevice::add_handlers()
{
	add_read_handler ("sent",    read_handler, h_sent);
	add_read_handler ("dropped", read_handler, h_dropped);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(FromBatchDevice userlevel)
EXPORT_ELEMENT(ToBatchDevice)
