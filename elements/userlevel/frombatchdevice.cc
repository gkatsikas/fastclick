// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * frombatchdevice.{cc,hh} -- element reads packets from Linux-based interfaces
 * Douglas S. J. De Couto, Eddie Kohler, John Jannotti
 *
 * Computational and syscall batching support
 * by Georgios Katsikas
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2001 International Computer Science Institute
 * Copyright (c) 2005-2007 Regents of the University of California
 * Copyright (c) 2011 Meraki, Inc.
 * Copyright (c) 2012 Eddie Kohler
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

#if !defined(__sun)
# include <sys/ioctl.h>
#else
# include <sys/ioccom.h>
#endif

#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

#include <click/config.h>
#include <click/error.hh>
#include <click/args.hh>

#include "fakepcap.hh"
#include "frombatchdevice.hh"

CLICK_DECLS

FromBatchDevice::FromBatchDevice() :
	_datalink(-1), _n_recv(0), _promisc(0),
	_snaplen(0), _fd(-1), _verbose(false)
{
#if HAVE_BATCH
	in_batch_mode = BATCH_MODE_YES;
#endif
	_pkts   = 0;
	_msgs   = 0;
	_iovecs = 0;
}

FromBatchDevice::~FromBatchDevice()
{
}

int
FromBatchDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
	bool promisc = false, outbound = false, sniffer = true, timestamp = true;
	_protocol   = 0;
	_snaplen    = default_snaplen;
	_headroom   = Packet::default_headroom;
	_headroom  += (4 - (_headroom + 2) % 4) % 4; // default 4/2 alignment
	_force_ip   = false;
	_burst_size = BATCHDEV_DEF_PREF_BATCH_SIZE;

	if (Args(conf, this, errh)
			.read_mp("DEVNAME",   _ifname)
			.read_p ("PROMISC",   promisc)
			.read_p ("SNAPLEN",   _snaplen)
			.read   ("SNIFFER",   sniffer)
			.read   ("FORCE_IP",  _force_ip)
			.read   ("PROTOCOL",  _protocol)
			.read   ("OUTBOUND",  outbound)
			.read   ("HEADROOM",  _headroom)
			.read   ("BURST",     _burst_size)
			.read   ("TIMESTAMP", timestamp)
			.read   ("VERBOSE",   _verbose)
			.complete() < 0)
		return -1;

	if ( _snaplen > 65535 || _snaplen < 14 )
		return errh->error("[%s] [%s] SNAPLEN out of range", name().c_str(), _ifname.c_str());
	if ( _headroom > 8190 )
		return errh->error("[%s] [%s] HEADROOM out of range", name().c_str(), _ifname.c_str());
	if ( _burst_size <= 0 )
		return errh->error("[%s] [%s] BURST out of range", name().c_str(), _ifname.c_str());
	_protocol = htons(_protocol);

	_sniffer   = sniffer;
	_promisc   = promisc;
	_outbound  = outbound;
	_timestamp = timestamp;

#if HAVE_BATCH
	if ( _force_ip )
		return errh->error("[%s] [%s] FORCE_IP option not supported in batch mode",
			name().c_str(), _ifname.c_str());

	if ( _verbose )
		click_chatter("[%s] [%s] Rx will batch up to BURST (%d) packets",
				name().c_str(), _ifname.c_str(), _burst_size);

	if ( (_burst_size < BATCHDEV_MIN_PREF_BATCH_SIZE) || (_burst_size > BATCHDEV_MAX_PREF_BATCH_SIZE) )
		errh->warning("[%s] [%s] To improve the I/O performance set a BURST value in [%d-%d], preferably %d.",
				name().c_str(), _ifname.c_str(), BATCHDEV_MIN_PREF_BATCH_SIZE, BATCHDEV_MAX_PREF_BATCH_SIZE,
				BATCHDEV_DEF_PREF_BATCH_SIZE);
#endif

	return 0;
}

int
FromBatchDevice::initialize(ErrorHandler *errh)
{
	if ( !_ifname )
		return errh->error("[%s] Interface not set", name().c_str());

	_fd = open_packet_socket(_ifname, errh);
	if (_fd < 0)
		return -1;

	int promisc_ok = set_promiscuous(_fd, _ifname, _promisc);
	if ( promisc_ok < 0 ) {
		if (_promisc)
			errh->warning("[%s] Cannot set promiscuous mode", name().c_str());
		_was_promisc = -1;
	}
	else {
		_was_promisc = promisc_ok;
	}

	_datalink = FAKE_DLT_EN10MB;

	if ( _fd >= 0 )
		add_select(_fd, SELECT_READ);

	if ( !_sniffer )
		if (KernelFilter::device_filter(_ifname, true, errh) < 0)
			_sniffer = true;

	// Pre-allocate memory for '_burst_size' packets
	_msgs = (struct mmsghdr *)  malloc(_burst_size * sizeof(struct mmsghdr));
	if ( !_msgs )
		return errh->error("[%s] [%s] Cannot pre-allocate message buffers",
			name().c_str(), _ifname.c_str());
	memset(_msgs, 0, _burst_size * sizeof(struct mmsghdr));

	_iovecs = (struct iovec *)  malloc(_burst_size * sizeof(struct iovec));
	if ( !_iovecs )
		return errh->error("[%s] [%s] Cannot pre-allocate ring buffers",
			name().c_str(), _ifname.c_str());
	memset(_iovecs, 0, _burst_size * sizeof(struct iovec));

	_pkts = (WritablePacket **) malloc(_burst_size * sizeof(Packet *));
	if ( !_pkts )
		return errh->error("[%s] [%s] Cannot pre-allocate packet buffers",
			name().c_str(), _ifname.c_str());
	memset(_pkts, 0, _burst_size * sizeof(Packet *));

	for (unsigned short i = 0; i < _burst_size; i++) {
		// Allocate a large enough space for each packet
		_pkts  [i] = Packet::make(_headroom, 0, _snaplen, 0);
		// Point the I/O vectors to the buffer of Click packets
		_iovecs[i].iov_base           = _pkts[i]->data();
		_iovecs[i].iov_len            = _pkts[i]->length();
		// Message structure understood by the recvmmsg syscall
		_msgs  [i].msg_hdr.msg_iov    = &_iovecs[i];
		_msgs  [i].msg_hdr.msg_iovlen = 1;
	}

	return 0;
}

void
FromBatchDevice::cleanup(CleanupStage stage)
{
	if ( stage >= CLEANUP_INITIALIZED && !_sniffer )
		KernelFilter::device_filter(_ifname, false, ErrorHandler::default_handler());

	if ( _fd >= 0 ) {
		if ( _was_promisc >= 0 )
			set_promiscuous(_fd, _ifname, _was_promisc);
		close(_fd);
	}

	_fd = -1;

	for (unsigned short i = 0; i < _burst_size; i++) {
		if ( _pkts[i] )
			_pkts[i]->kill();
		_pkts[i] = NULL;
	}
	if ( _pkts )
		free(_pkts);
	if ( _msgs )
		free(_msgs);
	if ( _iovecs )
		free(_iovecs);
}

int
FromBatchDevice::open_packet_socket(String ifname, ErrorHandler *errh)
{
	int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if ( fd == -1 )
		return errh->error("%s: socket: %s", ifname.c_str(), strerror(errno));

	// Get interface index
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name));
	int res = ioctl(fd, SIOCGIFINDEX, &ifr);
	if ( res != 0 ) {
		close(fd);
		return errh->error("%s: SIOCGIFINDEX: %s", ifname.c_str(), strerror(errno));
	}
	int ifindex = ifr.ifr_ifindex;

	// Bind to the specified interface.
	sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family   = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex  = ifindex;
	res = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if ( res != 0 ) {
		close(fd);
		return errh->error("Error on %s while binding: %s", ifname.c_str(), strerror(errno));
	}

	// Non-blocking I/O on the packet socket so we can poll
	fcntl(fd, F_SETFL, O_NONBLOCK);

	return fd;
}

int
FromBatchDevice::set_promiscuous(int fd, String ifname, bool promisc)
{
	// Get interface flags
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0)
		return -2;

	int was_promisc = (ifr.ifr_flags & IFF_PROMISC ? 1 : 0);

	// Set or reset promiscuous flag
#ifdef SOL_PACKET
	if (ioctl(fd, SIOCGIFINDEX, &ifr) != 0)
		return -2;

	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = (promisc ? PACKET_MR_PROMISC : PACKET_MR_ALLMULTI);

	if ( setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0 )
		return -3;
#else
	if ( was_promisc != (int) promisc ) {
		ifr.ifr_flags = (promisc ? ifr.ifr_flags | IFF_PROMISC : ifr.ifr_flags & ~IFF_PROMISC);
		if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
			return -3;
	}
#endif

	return was_promisc;
}

/*
 * Reading packets from the socket is implemented in a different way
 * such that the number of performed syscalls is greatly reduced to
 * amortize their overhead.
 */
void
FromBatchDevice::selected(int, int)
{
	unsigned short i;

#if HAVE_BATCH
	PacketBatch    *head = NULL;
	WritablePacket *last = NULL;
#endif

	// Ask for a batch of packets with a single syscall.
	int pkts_no = recvmmsg(_fd, _msgs, _burst_size, 0, NULL);
	// click_chatter("[%s] [%s] %4d packets received", name().c_str(), _ifname.c_str(), pkts_no);

	// Something went wrong. Release the memory and re-schedule
	if ( pkts_no == -1 ) {
		if ( _verbose ) {
			click_chatter("[%s] [%s] Error in recvfrom: %s",
				name().c_str(), _ifname.c_str(), strerror(errno));
		}
	}

	// We have a batch of packets at hand
	for (i = 0; i < pkts_no; i++) {
		if ( _msgs[i].msg_len > _snaplen ) {
			assert(_pkts[i]->length() == (uint32_t)_snaplen);
			SET_EXTRA_LENGTH_ANNO(_pkts[i], _msgs[i].msg_len - _snaplen);
		}
		else {
			_pkts[i]->take(_snaplen - _msgs[i].msg_len);
		}

		_pkts[i]->set_packet_type_anno(Packet::HOST);
		_pkts[i]->set_mac_header(_pkts[i]->data());

		// click_chatter(
		// 	"[%s] [%s] Packet with size %d",
		// 	name().c_str(), _ifname.c_str(), _pkts[i]->length()
		// );

	#if HAVE_BATCH
		// Build-up the batch packet-by-packet
		if ( head == NULL )
			head = PacketBatch::start_head(_pkts[i]);
		else
			last->set_next(_pkts[i]);
		last = _pkts[i];
	#else
		output(0).push(_pkts[i]);
	#endif
	}

#if HAVE_BATCH
	// Assimilate the batch
	if ( head && pkts_no > 0 ) {
		head->make_tail  (last, pkts_no);
		output_push_batch(0, head);
		_n_recv += pkts_no;
	}
#else
	_n_recv += pkts_no;
#endif

	// Reset the buffers for the next batch
	for (i = 0; i < _burst_size; i++) {
	//	_pkts  [i]->initialize_data();
		_pkts  [i] = Packet::make(_headroom, 0, _snaplen, 0);
		_iovecs[i].iov_base = _pkts[i]->data();
		_iovecs[i].iov_len  = _pkts[i]->length();
	}

	return;
}

void
FromBatchDevice::kernel_drops(bool &known, int &max_drops) const
{
	known = false, max_drops = -1;

#if defined(PACKET_STATISTICS)
	struct tpacket_stats stats;
	socklen_t statsize = sizeof(stats);
	if (getsockopt(_fd, SOL_PACKET, PACKET_STATISTICS, &stats, &statsize) >= 0)
		known = true, max_drops = stats.tp_drops;
#endif
}

String
FromBatchDevice::read_handler(Element *e, void *thunk)
{
	FromBatchDevice *fd = static_cast<FromBatchDevice *>(e);
	if (thunk == (void *) 0) {
		int  max_drops;
		bool known;

		fd->kernel_drops(known, max_drops);

		if (known)
			return String(max_drops);
		else if (max_drops >= 0)
			return "<" + String(max_drops);
		else
			return "??";
	}
	else if (thunk == (void *) 1)
		return String(fd->_n_recv);
}

int
FromBatchDevice::write_handler(const String &, Element *e, void *, ErrorHandler *)
{
	FromBatchDevice *fd = static_cast<FromBatchDevice *>(e);
	fd->_n_recv = 0;
	return 0;
}

void
FromBatchDevice::add_handlers()
{
	add_read_handler ("kernel_drops", read_handler,  0);
	add_read_handler ("count",        read_handler,  1);
	add_write_handler("reset_counts", write_handler, 0, Handler::BUTTON);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel KernelFilter)
EXPORT_ELEMENT(FromBatchDevice)
