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
#include "tommapdevice.hh"
#include <click/error.hh>
#include <click/etheraddress.hh>
#include <click/args.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <click/userutils.hh>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <features.h>

CLICK_DECLS

ToMMapDevice::ToMMapDevice()
	: 	_iqueues(), _iqueue_size(1024), _blocking(false),
		_packets_total(0), _bytes_total(0), _ring(0), _q(0),
		_burst_size(-1), _timeout(0), _congestion_warning_printed(false)
{
#if HAVE_BATCH
	_q_batch = 0;
#endif
}

ToMMapDevice::~ToMMapDevice()
{
}

int
ToMMapDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
	int maxthreads = -1;
	int maxqueues = 128;

	if (Args(conf, this, errh)
		.read_mp("DEVNAME", _ifname)
		.read("IQUEUE",     _iqueue_size)
		.read("MAXQUEUES",   maxqueues)
		.read("MAXTHREADS",  maxthreads)
		.read("BLOCKING",   _blocking)
		.read("BURST",      _burst_size)
		.read("MAXQUEUES",   maxqueues)
		.read("TIMEOUT",    _timeout)
		.read("NDESC",       ndesc)
		.read("VERBOSE",    _verbose)
		.complete() < 0)
	return -1;

	QueueDevice::configure_tx(maxthreads, 1, maxqueues, errh);

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
#if HAVE_BATCH
	if (batch_mode() == BATCH_MODE_YES) {
		//if (_burst_size > 0)
		//	errh->warning("[%s] BURST is unused with batching!", name().c_str());
	} else
#endif
	{
		if (_burst_size < 0)
			_burst_size = 32;
	}

	int ret = initialize_tx(errh);
	if (ret != 0) return ret;
//	click_chatter("[%s] [%s] Init Tx", name().c_str(), _ifname.c_str());

	ret = MMapDevice::add_tx_device(_ifname, _burst_size);
	if (ret != 0) return ret;
//	click_chatter("[%s] [%s] Add Tx", name().c_str(), _ifname.c_str());

	FromMMapDevice *fd = find_fromdevice();
	_ring = fd->get_fromdevice_mmap(_ifname, errh);
//	click_chatter("[%s] [%s] Get Tx ring", name().c_str(), _ifname.c_str());

	bool existed = false;
	_fd = fd->get_fromdevice_fd(_ifname, &existed, errh);
//	click_chatter("[%s] [%s] Get Tx FD", name().c_str(), _ifname.c_str());

	// Check for duplicate writers
	void *&used = router()->force_attachment("device_writer_" + _ifname);
	if ( used )
		return errh->error("[%s] [%s] Duplicate writer for this device", name().c_str(), _ifname.c_str());
	used = this;

	ret = MMapDevice::setup_poll(_ifname, _ring, TX_MODE);
	if ( ret != 0 ) return ret;
//	click_chatter("[%s] [%s] Tx Polling configured on %d", name().c_str(), _ifname.c_str(), _fd);

	ret = initialize_tasks(false, errh);
	if (ret != 0) return ret;

	// Queue allocation
	for (unsigned i = 0; i < _iqueues.size();i++) {
		_iqueues.get_value(i).pkts = new Packet *[_iqueue_size];
		if (_timeout >= 0) {
			_iqueues.get_value(i).timeout.assign(this);
			_iqueues.get_value(i).timeout.initialize(this);
			_iqueues.get_value(i).timeout.move_thread(i);
		}
	}
	click_chatter("[%s] [%s] %d internal queues allocated %d packet buffers",
				name().c_str(), _ifname.c_str(), _iqueues.size(), _iqueue_size);

	pthread_t t_send;
	/*
	pthread_attr_t t_attr_send;
	struct sched_param para_send;
	pthread_attr_init(&t_attr_send);
	pthread_attr_setschedpolicy(&t_attr_send,SCHED_RR);
	para_send.sched_priority=20;
	pthread_attr_setschedparam(&t_attr_send, &para_send);
	*/
	if ( pthread_create(&t_send, 0, &task_send, (void *)(&_ring->sock_fd)) != 0 ) {
		click_chatter("[%s] [%s] Cannot start send task", name().c_str(), _ifname.c_str());
		return -1;
	}

	return 0;
}

void
ToMMapDevice::cleanup(CleanupStage)
{
	/*
	if (_fd >= 0 && _my_fd) {
		if ( MMapDevice::unmap_ring(_ifname) != 0 ) {
			click_chatter("[%s] Failed to release mmap", _ifname.c_str());
			return;
		}
	}
	_fd = -1;
	*/
	click_chatter("[%s] [%s] Cleanup", name().c_str(), _ifname.c_str());
	cleanup_tasks();
	for (unsigned i = 0; i < _iqueues.size();i++) {
			delete[] _iqueues.get_value(i).pkts;
	}
}

void
ToMMapDevice::run_timer(Timer *)
{
	flush_internal_queue( _iqueues.get() );
}

void *ToMMapDevice::task_send(void *arg) {
	int sent_bytes;
	int sock_fd = *((int *) arg);
	bool blocking = true;

	do
	{
		/* send all buffers with TP_STATUS_SEND_REQUEST */
		/* Wait end of transfer */
		sent_bytes = sendto(sock_fd, NULL, 0, (blocking? 0 : MSG_DONTWAIT), NULL, 0);
		//	(struct sockaddr *) ps_sockaddr, sizeof(struct sockaddr_ll)	);

	//	click_chatter("send() end (ec=%d)\n",sent_bytes);

		if( sent_bytes < 0 ) {
			//click_chatter("Send error (ec=%d)\n", sent_bytes);
			break;
		}
		else if ( sent_bytes == 0 ) {
			/* nothing to do => schedule : useful if no SMP */
			usleep(0);
		}
		else {
		//	click_chatter("[Tx thread] Sent %d bytes\n", sent_bytes);
		//	fflush(0);
		}
	} while( blocking );

	return reinterpret_cast<void*>(sent_bytes);
}

int
ToMMapDevice::walk_tx_ring_batch(const String ifname, struct ring *ring, PacketBatch *batch)
{
	if ( (ring == NULL) || (ring->ifname != ifname) ) {
		click_chatter("[%s] [Walk Tx Ring] Failed to find memory region for this device", ifname.c_str());
		return -1;
	}

	union frame_map ppd;
//	int sock = ring->sock_fd;

	if ( !batch ) {
		click_chatter("[%s] [Tx thread] Bad packet batch\n", ifname.c_str());
		return -1;
	}

	/*
	DevInfo *info = _devs.findp(ifname);
	if ( !info ) {
		click_chatter("[%s] [Tx thread] Device not accessible\n", ifname.c_str());
		return -1;
	}
	*/

	const unsigned short burst_size = batch->count();

	///////////////////////////////////////////////////////////
	// IMPORTANT: Tx descriptors start right after the Rx ones
	///////////////////////////////////////////////////////////
	unsigned int frame_num = ring->tx_rd_idx;
	Packet* current = batch;
//	click_chatter("[%s] [Tx thread] Ring %p to transmit %d packets\n", ifname.c_str(), ring, burst_size);

	counter_t sent_pkts  = 0;
	counter_t sent_bytes = 0;

	while ( sent_pkts < burst_size ) {

		// Poll for more
		poll(&ring->tx_pfd, 1, 0);

		while (
			MMapDevice::tx_kernel_ready(ring->rd[frame_num].iov_base, ring->version) &&	(sent_pkts < burst_size)
		) {
		//	click_chatter("[%s] [Tx thread] START\n", ifname.c_str());
			Packet* next = current->next();

			ppd.raw = ring->rd[frame_num].iov_base;

			// The length of the cuurent packet in the batch
			size_t packet_len = current->length();
		//	click_chatter("[%s] [Tx thread] Packet %d with length %d bytes\n", ifname.c_str(), sent_pkts, packet_len);

			switch (ring->version) {
				case TPACKET_V1:
					ppd.v1->tp_h.tp_snaplen = packet_len;
					ppd.v1->tp_h.tp_len     = packet_len;

					memcpy(
						(uint8_t *) ppd.raw + TPACKET_HDRLEN - sizeof(struct sockaddr_ll),
						current->data(), packet_len
					);

					/*
					print_frame(
						(uint8_t *) ppd.raw + TPACKET_HDRLEN - sizeof(struct sockaddr_ll),
						packet_len
					);
					*/
					break;

				case TPACKET_V2:
					ppd.v2->tp_h.tp_snaplen = packet_len;
					ppd.v2->tp_h.tp_len     = packet_len;

					memcpy(
						(uint8_t *) ppd.raw + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll),
						current->data(), packet_len
					);
				//	ppd.raw += TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
				//	ppd.raw = (void*) current->data();
				//	ppd.raw -= TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

					//MMapDevice::print_frame(
					//	(uint8_t *) ppd.raw + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll),
					//	packet_len
					//);

					break;
				default:
					click_chatter("[%s] [Tx thread] Bad TPCAKET version\n", ifname.c_str());
					return -1;
			}

			MMapDevice::tx_user_ready(ppd.raw, ring->version);

			sent_bytes += packet_len;
			sent_pkts++;
			current = next;

			// Circular logic of the Tx ring buffer.
			// It starts right after the end of the Rx ring buffer.
		//	click_chatter("[%s] [Tx thread] Current FD %d\n", ifname.c_str(), frame_num);
			if ( frame_num < (ring->rx_rd_num + ring->tx_rd_num -1)) {
				++frame_num;
			}
			else {
				frame_num = ring->rx_rd_num;
			}
		//	click_chatter("[%s] [Tx thread] Next FD %d\n", ifname.c_str(), frame_num);
		//	click_chatter("[%s] [Tx thread] DONE\n", ifname.c_str());
		}

		// Transmit the whole batch
		//int ret = sendto(sock, NULL, 0, 0, NULL, 0);
		/*
		int ret = sendto(sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
		if ( ret < 0 ) {
			click_chatter("[%s] [Walk Tx] Failed to transmit the contents of the ring buffer", ifname.c_str());
			return -1;
		}
		*/

	//	info->update_tx_info(sent_pkts, sent_bytes);
	}

	ring->tx_rd_idx = frame_num;

//	click_chatter("[%s] [Walk Tx] Batch of %d packets (%u bytes) sent\n", ifname.c_str(), sent_pkts, sent_bytes);

	return sent_pkts;
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
	return walk_tx_ring_batch(_ifname, _ring, batch);
}
#endif

/* Flush as much as possible packets from a given internal queue to the DPDK
 * device. */
void
ToMMapDevice::flush_internal_queue(InternalQueue &iqueue) {
	unsigned sent = 0;
	unsigned r = 0;
	/* sub_burst is the number of packets DPDK should send in one call if
	* there is no congestion, normally 32. If it sends less, it means
	* there is no more room in the output ring and we'll need to come
	* back later. Also, if we're wrapping around the ring, sub_burst
	* will be used to split the burst in two, as rte_eth_tx_burst needs a
	* contiguous buffer space.
	*/
	unsigned sub_burst = 0;

	lock();

	do {
		sub_burst = iqueue.nr_pending > 32 ? 32 : iqueue.nr_pending;
		if (iqueue.index + sub_burst >= _iqueue_size)
			// The sub_burst wraps around the ring
			sub_burst = _iqueue_size - iqueue.index;

		for (unsigned short i=0 ; i<sub_burst ; i++) {
			if ( send_packet(iqueue.pkts[iqueue.index]) != 0 ) {
				click_chatter("Error while transmitting packet");
				return;
			}
			r++;
		}
		//r = rte_eth_tx_burst(_port_id, queue_for_thisthread_begin(), &iqueue.pkts[iqueue.index], sub_burst);

		iqueue.nr_pending -= r;
		iqueue.index += r;

		if (iqueue.index >= _iqueue_size) // Wrapping around the ring
			iqueue.index = 0;

		sent += r;
	} while (r == sub_burst && iqueue.nr_pending > 0);

	unlock();

	add_count(sent);

	// If ring is empty, reset the index to avoid wrap ups
	if (iqueue.nr_pending == 0)
		iqueue.index = 0;
}

void
ToMMapDevice::push_packet(int port, Packet *p)
{
	click_chatter("[%s] [%s] [Push packet]", name().c_str(), _ifname.c_str());

	// Get the thread-local internal queue
	InternalQueue &iqueue = _iqueues.get();

	bool congestioned;
	do {
		congestioned = false;

		// Internal queue is full
		if (iqueue.nr_pending == _iqueue_size) {
			/* We just set the congestion flag. If we're in blocking mode,
			* we'll loop, else we'll drop this packet.*/
			congestioned = true;
			if (!_blocking) {
				if (!_congestion_warning_printed)
					click_chatter("%s: packet dropped", name().c_str());
				_congestion_warning_printed = true;
			}
			else {
				if (!_congestion_warning_printed)
					click_chatter("%s: congestion warning", name().c_str());
				_congestion_warning_printed = true;
			}
		}
		// If there is space in the iqueue
		else {
			if ( p != NULL ) {
				iqueue.pkts[(iqueue.index + iqueue.nr_pending) % _iqueue_size] = p;
				iqueue.nr_pending++;
			}
		}

		if ( (int)iqueue.nr_pending >= _burst_size || congestioned ) {
			flush_internal_queue(iqueue);
			if (_timeout && iqueue.nr_pending == 0)
				iqueue.timeout.unschedule();
		}
		else if ( _timeout >= 0 && !iqueue.timeout.scheduled() ) {
			if ( _timeout == 0 )
				iqueue.timeout.schedule_now();
			else
				iqueue.timeout.schedule_after_msec(_timeout);
		}

	// If we're in blocking mode, we loop until we can put p in the iqueue
	} while ( unlikely(_blocking && congestioned) );

	if ( likely( is_fullpush() ) )
		p->safe_kill();
}

#if HAVE_BATCH
void ToMMapDevice::push_batch(int, PacketBatch *head)
{
//	click_chatter("[%s] [%s] [Push batch]", name().c_str(), _ifname.c_str());

	// Get the thread-local internal queue
	InternalQueue &iqueue = _iqueues.get();
	Packet *p = head;

#if HAVE_BATCH_RECYCLE
//	click_chatter("[%s] [%s] [Push batch] Recycle", name().c_str(), _ifname.c_str());
	BATCH_RECYCLE_START();
#endif

//	click_chatter("[%s] [%s] [Push batch] Before pending", name().c_str(), _ifname.c_str());

	Packet **pkts = iqueue.pkts;

//	click_chatter("[%s] [%s] [Push batch] Packets", name().c_str(), _ifname.c_str());

	// First transmit what already exists in the queue
	if ( iqueue.nr_pending ) {
	//	click_chatter("[%s] [%s] [Push batch] Pending Packets", name().c_str(), _ifname.c_str());
		PacketBatch    *pending_batch = NULL;
		WritablePacket *pending_last  = NULL;

		unsigned ret = 0;
		unsigned r;
		unsigned left = iqueue.nr_pending;
	//	click_chatter("[%s] [%s] [Push batch] Packets in queue %d", name().c_str(), _ifname.c_str(), left);

		for (unsigned short i=0 ; i<left ; i++) {
			if (pending_batch == NULL)
				pending_batch = PacketBatch::start_head(pkts[i]);
			else
				pending_last->set_next(pkts[i]);
			pending_last = static_cast<WritablePacket *> (pkts[i]);
		}
		if (pending_batch)
			pending_batch->make_tail(pending_last, left);
	//	click_chatter("[%s] [%s] [Push batch] Pending batch assimilated", name().c_str(), _ifname.c_str());
		r = send_batch(pending_batch);
		ret  += r;
		left -= r;

		// All sent
		if (ret == iqueue.nr_pending) {
			// Reset, there is nothing in the internal queue
			iqueue.nr_pending = 0;
			iqueue.index = 0;
		}
		// Place the new packets after the old
		else if (iqueue.index + iqueue.nr_pending + head->count() < _iqueue_size) {
			iqueue.index      += ret;
			iqueue.nr_pending -= ret;
			pkts = &iqueue.pkts[iqueue.index + iqueue.nr_pending];
		}
		// Place the new packets before the older
		else if ( (int)iqueue.index + (int)ret - (int)head->count() >= (int)0 ) {
			// click_chatter("Before !");
			iqueue.index = (unsigned int)((int)iqueue.index - (int)head->count() + (int)ret);
			iqueue.nr_pending -= ret;
			pkts = &iqueue.pkts[iqueue.index];
		}
		//Drop packets
		else {
			unsigned int lost = iqueue.nr_pending - ret;
			add_dropped(lost);
			//click_chatter("Dropped %d");
			for (unsigned i = iqueue.index + ret; i < iqueue.index + iqueue.nr_pending; i++) {
			//	rte_pktmbuf_free(iqueue.pkts[i]);
				iqueue.pkts[i]->kill();
			}
			click_chatter("Dropped !");

			//Reset, we will erase the old
			iqueue.index      = 0;
			iqueue.nr_pending = 0;
		}
	}

	// Fill the queue with the batch
//	click_chatter("[%s] [%s] [Push batch] Skipped pending", name().c_str(), _ifname.c_str());

	Packet **pkt = pkts;
	while ( p != NULL ) {
		Packet* next = p->next();
		*pkt = p;
	//	click_chatter("[%s] [%s] [Push batch] Assign", name().c_str(), _ifname.c_str());
		if ( *pkt == 0 ) {
	//		click_chatter("[%s] [%s] [Push batch] BAD PACKET POINTER", name().c_str(), _ifname.c_str());
			break;
		}
		BATCH_RECYCLE_UNSAFE_PACKET(p);
	//	click_chatter("[%s] [%s] [Push batch] Walk", name().c_str(), _ifname.c_str());
		pkt++;
		p = next;
	}

//	click_chatter("[%s] [%s] [Push batch] Before second round", name().c_str(), _ifname.c_str());

	////////////////////////////////
	// Leftovers
	////////////////////////////////
	PacketBatch    *pending_batch = NULL;
	WritablePacket *pending_last  = NULL;

	unsigned ret = 0;
	unsigned r;
	unsigned left = head->count() + iqueue.nr_pending;
//	click_chatter("[%s] [%s] [Push batch] To transmit %d packets", name().c_str(), _ifname.c_str(), left);

	for (unsigned short i=0 ; i<left ; i++) {
		if (pending_batch == NULL) {
			pending_batch = PacketBatch::start_head(pkts[i]);
		//	pending_batch = PacketBatch::start_head(iqueue.pkts[iqueue.index + i]);
		//	click_chatter("[%s] [%s] [Push batch] First packet added", name().c_str(), _ifname.c_str());
		}
		else {
			pending_last->set_next(pkts[i]);
		//	click_chatter("[%s] [%s] [Push batch] Next packet added ", name().c_str(), _ifname.c_str());
		}
		pending_last = static_cast<WritablePacket *> (pkts[i]);
	//	click_chatter("[%s] [%s] [Push batch] Casting", name().c_str(), _ifname.c_str());
	}
	if (pending_batch)
		pending_batch->make_tail(pending_last, left);
//	click_chatter("[%s] [%s] [Push batch] Ready to Tx", name().c_str(), _ifname.c_str());
	r = send_batch(pending_batch);
	ret  += r;

	add_count(ret);

	// All sent
	if ( ret == head->count() + iqueue.nr_pending ) {
		iqueue.index = 0;
		iqueue.nr_pending = 0;
	}
	else {
		iqueue.index = iqueue.index + ret;
		iqueue.nr_pending = head->count() + iqueue.nr_pending - ret;
	}

	#if HAVE_BATCH_RECYCLE
		BATCH_RECYCLE_END();
	#else
		head->kill();
	#endif
}
#endif

String
ToMMapDevice::read_handler(Element *e, void *thunk)
{
	ToMMapDevice *td = static_cast<ToMMapDevice*>(e);
	// Packet count
	if ( thunk == (void *) 0 )
		return String(td->_packets_total);
	// Byte count
	else if ( thunk == (void *) 1 )
		return String(td->_bytes_total);
	else
		return String(td->_packets_dropped);
}

void
ToMMapDevice::add_handlers()
{
	add_read_handler("count",   read_handler, 0);
	add_read_handler("bytes",   read_handler, 1);
	add_read_handler("dropped", read_handler, 2);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(FromMMapDevice userlevel)
EXPORT_ELEMENT(ToMMapDevice)
