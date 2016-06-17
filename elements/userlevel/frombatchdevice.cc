// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * frombatchdevice.{cc,hh} -- element reads packets live from network via pcap
 * Douglas S. J. De Couto, Eddie Kohler, John Jannotti
 *
 * Computational batching support
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

#include <click/config.h>
#include <sys/types.h>
#include <sys/time.h>

#if !defined(__sun)
# include <sys/ioctl.h>
#else
# include <sys/ioccom.h>
#endif

#include "frombatchdevice.hh"
#include <click/etheraddress.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/userutils.hh>
#include <unistd.h>
#include <fcntl.h>
#include "fakepcap.hh"

# include <sys/socket.h>
# include <net/if.h>
# include <features.h>
# include <linux/if_packet.h>
# include <net/ethernet.h>

CLICK_DECLS

FromBatchDevice::FromBatchDevice()
    : _datalink(-1), _count(0), _promisc(0), _snaplen(0), _fd(-1)
{
#if HAVE_BATCH
    in_batch_mode = BATCH_MODE_YES;
#endif
}

FromBatchDevice::~FromBatchDevice()
{
}

int
FromBatchDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
    bool promisc = false, outbound = false, sniffer = true, timestamp = true;
    _protocol = 0;
    _snaplen = default_snaplen;
    _headroom = Packet::default_headroom;
    _headroom += (4 - (_headroom + 2) % 4) % 4; // default 4/2 alignment
    _force_ip = false;
    _burst = 1;
    String bpf_filter, capture, encap_type;
    bool has_encap;
    if (Args(conf, this, errh)
	.read_mp("DEVNAME", _ifname)
	.read_p("PROMISC", promisc)
	.read_p("SNAPLEN", _snaplen)
	.read("SNIFFER", sniffer)
	.read("FORCE_IP", _force_ip)
	.read("METHOD", WordArg(), capture)
	.read("CAPTURE", WordArg(), capture) // deprecated
	.read("BPF_FILTER", bpf_filter)
	.read("PROTOCOL", _protocol)
	.read("OUTBOUND", outbound)
	.read("HEADROOM", _headroom)
	.read("ENCAP", WordArg(), encap_type).read_status(has_encap)
	.read("BURST", _burst)
	.read("TIMESTAMP", timestamp)
	.complete() < 0)
	return -1;
    if (_snaplen > 65535 || _snaplen < 14)
	return errh->error("SNAPLEN out of range");
    if (_headroom > 8190)
	return errh->error("HEADROOM out of range");
    if (_burst <= 0)
	return errh->error("BURST out of range");
    _protocol = htons(_protocol);

    // set _method
    if (capture == "") {
	_method = method_linux;
    }
    else if (capture == "LINUX")
	_method = method_linux;
    else
	return errh->error("bad METHOD");

    _sniffer = sniffer;
    _promisc = promisc;
    _outbound = outbound;
    _timestamp = timestamp;
    return 0;
}

int
FromBatchDevice::open_packet_socket(String ifname, ErrorHandler *errh)
{
    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1)
	return errh->error("%s: socket: %s", ifname.c_str(), strerror(errno));

    // get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name));
    int res = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (res != 0) {
	close(fd);
	return errh->error("%s: SIOCGIFINDEX: %s", ifname.c_str(), strerror(errno));
    }
    int ifindex = ifr.ifr_ifindex;

    // bind to the specified interface.  from packet man page, only
    // sll_protocol and sll_ifindex fields are used; also have to set
    // sll_family
    sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = ifindex;
    res = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (res != 0) {
	close(fd);
	return errh->error("%s: bind: %s", ifname.c_str(), strerror(errno));
    }

    // nonblocking I/O on the packet socket so we can poll
    fcntl(fd, F_SETFL, O_NONBLOCK);

    return fd;
}

int
FromBatchDevice::set_promiscuous(int fd, String ifname, bool promisc)
{
    // get interface flags
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0)
	return -2;
    int was_promisc = (ifr.ifr_flags & IFF_PROMISC ? 1 : 0);

    // set or reset promiscuous flag
#ifdef SOL_PACKET
    if (ioctl(fd, SIOCGIFINDEX, &ifr) != 0)
	return -2;
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type = (promisc ? PACKET_MR_PROMISC : PACKET_MR_ALLMULTI);
    if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
	return -3;
#else
    if (was_promisc != promisc) {
	ifr.ifr_flags = (promisc ? ifr.ifr_flags | IFF_PROMISC : ifr.ifr_flags & ~IFF_PROMISC);
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
	    return -3;
    }
#endif

    return was_promisc;
}

int
FromBatchDevice::initialize(ErrorHandler *errh)
{
    if (!_ifname)
	return errh->error("interface not set");

    _fd = open_packet_socket(_ifname, errh);
    if (_fd < 0)
	return -1;

    int promisc_ok = set_promiscuous(_fd, _ifname, _promisc);
    if (promisc_ok < 0) {
	if (_promisc)
		errh->warning("cannot set promiscuous mode");
	_was_promisc = -1;
    }
    else {
	_was_promisc = promisc_ok;
    }
    _datalink = FAKE_DLT_EN10MB;
    _method = method_linux;

    if (_fd >= 0)
	add_select(_fd, SELECT_READ);

    if (!_sniffer)
	if (KernelFilter::device_filter(_ifname, true, errh) < 0)
	    _sniffer = true;

    return 0;
}

void
FromBatchDevice::cleanup(CleanupStage stage)
{
    if (stage >= CLEANUP_INITIALIZED && !_sniffer)
	KernelFilter::device_filter(_ifname, false, ErrorHandler::default_handler());
    if ( _fd >= 0 ) {
	if (_was_promisc >= 0)
	    set_promiscuous(_fd, _ifname, _was_promisc);
	close(_fd);
    }
    _fd = -1;
}

void
FromBatchDevice::selected(int, int)
{
#if HAVE_BATCH
	PacketBatch    *head = NULL;
	WritablePacket *last = NULL;
#endif
	int nlinux = 0;
	while ( nlinux < _burst ) {
		struct sockaddr_ll sa;
		socklen_t fromlen = sizeof(sa);
		WritablePacket *p = Packet::make(_headroom, 0, _snaplen, 0);

		// Read from Linux socket
		int len = recvfrom(_fd, p->data(), p->length(), MSG_TRUNC, (sockaddr *)&sa, &fromlen);
		if ( len > 0 && (sa.sll_pkttype != PACKET_OUTGOING || _outbound )
			&& (_protocol == 0 || _protocol == sa.sll_protocol)) {

			if (len > _snaplen) {
				assert(p->length() == (uint32_t)_snaplen);
				SET_EXTRA_LENGTH_ANNO(p, len - _snaplen);
			}
			else
				p->take(_snaplen - len);
			p->set_packet_type_anno((Packet::PacketType)sa.sll_pkttype);
			p->timestamp_anno().set_timeval_ioctl(_fd, SIOCGSTAMP);
			p->set_mac_header(p->data());
			++nlinux;
			++_count;

			// Ready to push
			if ( !_force_ip || fake_pcap_force_ip(p, _datalink) ) {
			// In batch-mode
			#if HAVE_BATCH
				if (head == NULL)
					head = PacketBatch::start_head(p);
				else
					last->set_next(p);
				last = p;
			// Or regularly
			#else
				output(0).push(p);
			#endif
			}
			else {
				checked_output_push(1, p);
			}
		}
		else {
			p->kill();
			if (len <= 0 && errno != EAGAIN)
				click_chatter("FromBatchDevice(%s): recvfrom: %s", _ifname.c_str(), strerror(errno));
			break;
		}
	}

#if HAVE_BATCH
	if (head) {
		head->make_tail(last, nlinux);
		output_push_batch(0, head);
	}
#endif
}

void
FromBatchDevice::kernel_drops(bool& known, int& max_drops) const
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
FromBatchDevice::read_handler(Element* e, void *thunk)
{
    FromBatchDevice* fd = static_cast<FromBatchDevice*>(e);
    if (thunk == (void *) 0) {
	int max_drops;
	bool known;
	fd->kernel_drops(known, max_drops);
	if (known)
	    return String(max_drops);
	else if (max_drops >= 0)
	    return "<" + String(max_drops);
	else
	    return "??";
    } else if (thunk == (void *) 1)
	return String(fake_pcap_unparse_dlt(fd->_datalink));
    else
	return String(fd->_count);
}

int
FromBatchDevice::write_handler(const String &, Element *e, void *, ErrorHandler *)
{
    FromBatchDevice* fd = static_cast<FromBatchDevice*>(e);
    fd->_count = 0;
    return 0;
}

void
FromBatchDevice::add_handlers()
{
    add_read_handler("kernel_drops", read_handler, 0);
    add_read_handler("encap", read_handler, 1);
    add_read_handler("count", read_handler, 2);
    add_write_handler("reset_counts", write_handler, 0, Handler::BUTTON);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel FakePcap KernelFilter)
EXPORT_ELEMENT(FromBatchDevice)
