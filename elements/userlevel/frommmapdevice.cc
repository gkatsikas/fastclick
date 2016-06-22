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

#if !defined(__sun)
# include <sys/ioctl.h>
#else
# include <sys/ioccom.h>
#endif

#include <click/config.h>
#include <click/etheraddress.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/userutils.hh>

#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>

#include <poll.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <features.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

#include "frommmapdevice.hh"

CLICK_DECLS

FromMMapDevice::FromMMapDevice()
	:	_task(this), _packets_total(0), _bytes_total(0), _burst_size(32)
{
#if HAVE_BATCH
	in_batch_mode = BATCH_MODE_YES;
#endif
#if HAVE_NUMA
	_numa = true;
#else
	_numa = false;
#endif
	_nb_blocks = MMapDevice::NB_BLOCKS;
}

FromMMapDevice::~FromMMapDevice()
{
	click_chatter("[%s] Read: %d packets (%u bytes)", _ifname.c_str(), _packets_total, _bytes_total);
}

int
FromMMapDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
	int maxthreads   = -1;
	int minqueues    =  1;
	int maxqueues    =  128; //TODO Should be device dependent
	int numa_node    =  0;
	int threadoffset = -1;

	if (Args(conf, this, errh)
		.read_mp("DEVNAME", _ifname)
		.read("MAXTHREADS", maxthreads)
		.read("THREADOFFSET", threadoffset)
		.read("MINQUEUES",minqueues)
		.read("MAXQUEUES",maxqueues)
		.read("BURST", _burst_size)
		.read("NUMA", _numa)
		.complete() < 0)
		return -1;

	if (_numa) {
		numa_node = 0;
	}

	int r = QueueDevice::configure_rx(numa_node, maxthreads, minqueues, maxqueues, threadoffset, errh);
	if (r != 0)
		return r;
	return 0;
}

int
FromMMapDevice::initialize(ErrorHandler *errh)
{
	if ( !_ifname )
		return errh->error("Interface not set");

	int ret = QueueDevice::initialize_rx(errh);
	if (ret != 0) return ret;

	// TODO: Multiple queues?
	ret = MMapDevice::add_rx_device(_ifname, _burst_size);
	if (ret != 0) return ret;
//	click_chatter("[%s] Add Rx device", _ifname.c_str());

	ret = MMapDevice::initialize(errh);
	if ( ret != 0 ) return ret;
//	click_chatter("[%s] Init done", _ifname.c_str());

	ret = QueueDevice::initialize_tasks(true, errh);
	if ( ret != 0 ) return ret;
//	click_chatter("[%s] Queue init done", _ifname.c_str());

	_ring = MMapDevice::get_ring(_ifname);

	int fd = -1;
	if ( !_ring ) {
		fd = setup_device(_ifname, &_ring, errh);
	//	click_chatter("[%s] Device setup", _ifname.c_str());
	}
	else {
		fd = _ring->sock_fd;
	}

	ret = MMapDevice::setup_poll(_ifname, _ring, RX_MODE);
	if ( ret != 0 ) return ret;
	click_chatter("[%s] Rx Polling configured on %d", _ifname.c_str(), fd);

	//ScheduleInfo::initialize_task(this, &_task, false, errh);
	add_select(fd, SELECT_READ);

	return 0;
}

void
FromMMapDevice::cleanup(CleanupStage stage)
{
	click_chatter("[%s] Cleanup", _ifname.c_str());

	if ( _ring ) {
		if ( MMapDevice::unmap_ring(_ifname) != 0 ) {
			click_chatter("[%s] Failed to release mmap", _ifname.c_str());
			return;
		}
		if ( _ring->sock_fd >= 0 )
			remove_select(_ring->sock_fd, SELECT_READ);
	}
}

int
FromMMapDevice::setup_device(const String ifname, struct ring **ring, ErrorHandler *errh)
{
	*ring = MMapDevice::alloc_ring(ifname);
	if ( ! *ring ) {
		return errh->error("[%s] Cannot allocate memory", ifname.c_str());
	}
//	click_chatter("[%s] Alloc", ifname.c_str());

	// Open the socket
	int fd = MMapDevice::open_socket(ifname, *ring, TPACKET_V2);
	if ( fd < 0 ) {
		return errh->error("[%s] Bad file descriptor", ifname.c_str());
	}
//	click_chatter("[%s] Socket %d is setup", ifname.c_str(), fd);

	// Setup ring buffer
	int ret = MMapDevice::setup_ring(ifname, *ring, TPACKET_V2);
	if ( ret != 0 ) {
		return errh->error("[%s] Failed to setup ring buffers", ifname.c_str());
	}
//	click_chatter("[%s] Ring buffers are setup", ifname.c_str());

	// Map memory
	ret = MMapDevice::mmap_ring(ifname, *ring);
	if ( ret != 0 ) {
		return errh->error("[%s] Failed to map memory", ifname.c_str());
	}
	click_chatter("[%s] Memory is mapped", ifname.c_str());

	// Bind socket
	ret = MMapDevice::bind_ring(ifname, *ring);
	if ( ret != 0 ) {
		return errh->error("[%s] Ring bind", ifname.c_str());
	}
//	click_chatter("[%s] Ring bound", ifname.c_str());

	return fd;
}

void
FromMMapDevice::selected(int fd, int)
{
	if (fd != _ring->sock_fd)
		return;

	receive_packets();
	_task.fast_reschedule();
}

bool
FromMMapDevice::run_task(Task *t)
{
	int ret = receive_packets();
	_task.fast_reschedule();

	return (ret == 0);
}

#if HAVE_BATCH
void
FromMMapDevice::walk_rx_ring_batch(const String ifname, struct ring *ring) {
	union frame_map ppd;
	//unsigned int frame_num = ring->rx_rd_idx;
	unsigned int frame_num = 0;

	PacketBatch    *head = NULL;
	WritablePacket *last = NULL;

	//click_chatter("[%s] [Rx thread] Ring %p\n", ifname.c_str(), ring);

	/*
	DevInfo *info = _devs.findp(ifname);
	if ( !info ) {
		click_chatter("[%s] [Walk Rx Ring] Device not accessible\n", ifname.c_str());
		return;
	}
	*/

	//const unsigned short burst_size = info->get_burst_size();
	const unsigned short burst_size = _burst_size;
	click_chatter("[%s] [Rx thread] BURST %d\n", ifname.c_str(), burst_size);

	counter_t recv_pkts  = 0;
	counter_t recv_bytes = 0;

	while (1) {

		while (
			MMapDevice::rx_kernel_ready(ring->rd[frame_num].iov_base, ring->version) && (recv_pkts < burst_size)
		) {
			ppd.raw = ring->rd[frame_num].iov_base;

			uint8_t *frame = NULL;
			unsigned int snap_len = 0;
			const struct sockaddr_ll *sll;

			switch (ring->version) {
				case TPACKET_V1:
					snap_len = ppd.v1->tp_h.tp_snaplen;
					frame    = (uint8_t *) ppd.raw + ppd.v1->tp_h.tp_mac;
					sll      = (const struct sockaddr_ll *) (
						ring->rd[frame_num].iov_base + TPACKET_ALIGN(sizeof(struct tpacket_hdr))
					);
					break;

				case TPACKET_V2:
					snap_len = ppd.v2->tp_h.tp_snaplen;
					frame    = (uint8_t *) ppd.raw + ppd.v2->tp_h.tp_mac;
					sll      = (const struct sockaddr_ll *) (
						ring->rd[frame_num].iov_base + TPACKET_ALIGN(sizeof(struct tpacket2_hdr))
					);
					break;
				default:
					return;
			}

			WritablePacket *p = Packet::make(Packet::default_headroom, frame, snap_len, 0);
			p->timestamp_anno().set_timeval_ioctl(ring->sock_fd, SIOCGSTAMP);
			p->set_packet_type_anno((Packet::PacketType)sll->sll_pkttype);
			p->set_mac_header(p->data());

			// Aggregate input packets in a batch list
			if (head == NULL)
				head = PacketBatch::start_head(p);
			else
				last->set_next(p);
			last = p;

		//	MMapDevice::print_frame(p->data(), snap_len);
			MMapDevice::rx_user_ready(ppd.raw, ring->version);

			recv_pkts++;
			recv_bytes += snap_len;
			frame_num   = (frame_num + 1) % ring->rx_rd_num;
		}

		if ( recv_pkts == burst_size ) {
		if ( head ) {
			head->make_tail(last, recv_pkts);
			output_push_batch(0, head);

		//	info->update_rx_info(recv_pkts, recv_bytes);
		//	click_chatter("[%s] [Rx thread] PUSH %d packets (%d bytes)\n", ifname.c_str(), recv_pkts, recv_bytes);

			_packets_total += recv_pkts;
			_bytes_total   += recv_bytes;

		//	head->kill();
			head = NULL;
			recv_pkts  = 0;
			recv_bytes = 0;
		}
		}
		poll(&ring->rx_pfd, 1, 0);
	}

	if ( MMapDevice::unmap_ring(ifname) != 0 ) {
		click_chatter("[%s] Failed to release mmap", ifname.c_str());
		return;
	}
	click_chatter("[%s] [Rx thread] Terminated after receiving %d packets (%d bytes)\n",
				ifname.c_str(), _packets_total, _bytes_total);

	//click_chatter("[%s] [Walk Rx Ring] %d packets (%u bytes) received: Current RD: %d\n",
	//				ifname.c_str(), recv_pkts, recv_bytes, frame_num);
}
#endif

unsigned int
FromMMapDevice::receive_packets()
{
#if HAVE_BATCH
	/*
	PacketBatch *batch = MMapDevice::walk_rx_ring_batch(_ifname, _ring);
	if ( !batch ) {
		click_chatter("[%s] [Receive] Invalid batch", _ifname.c_str());
		batch->kill();
		return -1;
	}
	_packets_total += batch->count();
	output_push_batch(0, batch);
	*/
	walk_rx_ring_batch(_ifname, _ring);

//	click_chatter("[%s] [BATCH] On receive: %d packets", _ifname.c_str(), batch->count());
#else
	Packet *packet = MMapDevice::walk_rx_ring_packet(_ifname, _ring);
	if ( !packet ) {
		click_chatter("[%s] [Receive] Invalid packet", _ifname.c_str());
		packet->kill();
		return -1;
	}
	_packets_total ++;
	output(0).push(packet);
//	click_chatter("[%s] On receive: 1 packet", _ifname.c_str());
#endif

	return 0;
}

String
FromMMapDevice::read_handler(Element *e, void *thunk)
{
	FromMMapDevice *fd = static_cast<FromMMapDevice*>(e);
	// Packet count
	if (thunk == (void *) 0)
		return String(fd->_packets_total);
	// Byte count
	else
		return String(fd->_bytes_total);
}

int
FromMMapDevice::write_handler(const String &, Element *e, void *, ErrorHandler *)
{
	FromMMapDevice *fd = static_cast<FromMMapDevice*>(e);
	fd->_packets_total = 0;
	fd->_bytes_total   = 0;
	return 0;
}

void
FromMMapDevice::add_handlers()
{
	add_read_handler("count",         read_handler,  0);
	add_read_handler("bytes",         read_handler,  1);
	add_write_handler("reset_counts", write_handler, 0, Handler::BUTTON);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(FromMMapDevice)
ELEMENT_MT_SAFE(FromMMapDevice)
