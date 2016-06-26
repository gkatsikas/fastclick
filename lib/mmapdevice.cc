/*
 * mmapdevice.{cc,hh} -- library for interfacing with packet mmap
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

#include <time.h>             /* struct timespec */
#include <errno.h>            /* errno, perror, etc */
#include <fcntl.h>            /* open */
#include <stdlib.h>           /* calloc, free */
#include <string.h>           /* memcpy */
#include <unistd.h>           /* close */
#include <sys/ioctl.h>        /* ioctl */
#include <arpa/inet.h>        /* htons, ntohs */
#include <sys/socket.h>       /* socket */

#include <net/if.h>           /* if_nametoindex */
#include <netinet/udp.h>      /* udphdr  */
#include <netinet/tcp.h>      /* tcphdr  */
#include <netinet/ip_icmp.h>  /* icmphdr */

#include <click/config.h>
#include <click/packet.hh>
#include <click/mmapdevice.hh>

CLICK_DECLS

int  MMapDevice::NB_BLOCKS       = 128;
int  MMapDevice::BLOCK_SIZE      = sysconf(_SC_PAGESIZE) << 1;
int  MMapDevice::MTU_SIZE        = 1526;
bool MMapDevice::_debug          = false;
bool MMapDevice::_verbose        = false;
bool MMapDevice::_is_initialized = false;

HashMap<String, MMapDevice::DevInfo> MMapDevice::_devs;
HashMap<String, struct ring *>       MMapDevice::_ring_pool;

int
MMapDevice::initialize(ErrorHandler *errh)
{
	if ( _is_initialized )
		return 0;

	_is_initialized = true;
	if ( _verbose )
		click_chatter("[MMap Init] Successful");

	return 0;
}

int
MMapDevice::static_cleanup()
{
	if ( !_is_initialized )
		return 0;

	for ( HashMap<String, DevInfo>::const_iterator it = _devs.begin();
			it != _devs.end(); ++it )
		unmap_ring(it.key());
}

void
MMapDevice::set_debug_info(bool &verbose, bool &debug) {
	_verbose = verbose;
	_debug   = debug;
}

bool
MMapDevice::has_device(const String ifname)
{
	DevInfo *info = _devs.findp(ifname);
	if ( !info )
		return false;
	return true;
}

int
MMapDevice::add_device(const String ifname, Mode mode, unsigned short burst_size)
{
	DevInfo *info = _devs.findp(ifname);
	if ( !info ) {
		_devs.insert(ifname, DevInfo(burst_size));
		info = _devs.findp(ifname);
		if ( _verbose )
			click_chatter("[MMap Dev] Added %s device %s", mode==RX_MODE? "Rx":"Tx", ifname.c_str());
	}
	else {
		if ( _verbose )
			click_chatter("[MMap Dev] Added %s device %s", mode==RX_MODE? "Rx":"Tx", ifname.c_str());
	}

	if ( mode == RX_MODE ) {
		info->rx = true;
	}
	else {
		info->tx = true;
	}

	return 0;
}

int
MMapDevice::add_rx_device(const String ifname, unsigned short burst_size)
{
	return add_device(ifname, RX_MODE, burst_size);
}

int
MMapDevice::add_tx_device(const String ifname, unsigned short burst_size)
{
	return add_device(ifname, TX_MODE, burst_size);
}

struct ring *
MMapDevice::get_ring(const String ifname)
{
	if ( !has_device(ifname) )
		return NULL;
	return _ring_pool[ifname];
}

struct ring *
MMapDevice::alloc_ring(const String ifname)
{
	if ( has_device(ifname) && _ring_pool[ifname] ) {
		click_chatter("[%s] [Allocate Ring] Ring already allocated", ifname.c_str());
		return _ring_pool[ifname];
	}

	// Allocate a new ring for this interface
	struct ring *ring = (struct ring*) calloc(1, sizeof(*ring));
	if ( ring ) {
		memset(ring, 0, sizeof(*ring));
		ring->sock_fd    = -1;
		ring->mmap_len   = 0;
		ring->mmap_base  = NULL;
		ring->rd_len     = 0;
		ring->rd         = NULL;
		ring->rx_rd_addr = NULL;
		ring->tx_rd_addr = NULL;
	}

	if ( _verbose )
		click_chatter("[%s] [Allocate Ring] Successful allocation", ifname.c_str());

	// Add it to the map
	_ring_pool.insert(ifname, ring);

	return ring;
}

int
MMapDevice::open_socket(const String ifname, struct ring *ring, int ver)
{
	if ( ring->sock_fd > 0 ) {
		click_chatter("[%s] [Open Socket] Socket already open", ifname.c_str());
		return ring->sock_fd;
	}

	int sock_fd = socket(PF_PACKET, SOCK_TYPE, htons(SOCK_PROTO));
	if ( sock_fd <= 0 ) {
		click_chatter("[%s] [Open Socket] Failed to create socket", ifname.c_str());
		return -1;
	}

	int ret = setsockopt(sock_fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
	if ( ret < 0 ) {
		click_chatter("[%s] [Open Socket] Failed to set socket options", ifname.c_str());
		return -1;
	}

	ring->sock_fd = sock_fd;

	return sock_fd;
}

int
MMapDevice::setup_ring(const String ifname, struct ring *ring, int version)
{
	if ( !has_device(ifname) || ( !ring ) ) {
		click_chatter("[%s] [Setup Ring] Failed to identify this device", ifname.c_str());
		return -1;
	}

	int ret  = 0;
	int sock = ring->sock_fd;
	unsigned int blocks = MMapDevice::NB_BLOCKS;

	ring->version = version;

	switch (version) {
		case TPACKET_V1:
		case TPACKET_V2:
			set_packet_loss_discard(sock);
			configure_ring(ring, blocks);

			ret  = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &ring->rx_req,
								sizeof(ring->rx_req));

			ret |= setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &ring->tx_req,
								sizeof(ring->tx_req));
			break;
		default:
			click_chatter("[%s] [Setup Ring] TPACKET version not supported", ifname.c_str());
			return -1;
	}

	if (ret == -1) {
		click_chatter("[%s] [Setup Ring] Failed to set TPACKET socket options", ifname.c_str());
		return -1;
	}

	ring->rd_len = ring->rd_num * sizeof(*ring->rd);
	ring->rd     = (struct iovec *) malloc(ring->rd_len);
	if ( !ring->rd ) {
		click_chatter("[%s] [Setup Ring] Failed to allocate ring descriptors", ifname.c_str());
		return -1;
	}

	if ( _verbose )
		click_chatter("[%s] [Setup Ring] Successfull", ifname.c_str());

	return 0;
}

int
MMapDevice::mmap_ring(const String ifname, struct ring *ring)
{
	if ( !has_device(ifname) || !ring ) {
		click_chatter("[%s] [MMap  Ring] Failed to identify this device", ifname.c_str());
		return -1;
	}

	if ( (ring->mmap_len <= 0) || (ring->sock_fd <= 0) ) {
		click_chatter("[%s] [MMap  Ring] Invalid configuration", ifname.c_str());
		return -1;
	}

	ring->mmap_base = mmap(
		0, ring->mmap_len, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_LOCKED | MAP_POPULATE, ring->sock_fd, 0
	);
	if ( ring->mmap_base == MAP_FAILED ) {
		click_chatter("[%s] [MMap  Ring] Failed to map memory region", ifname.c_str());
		return -1;
	}

	memset(ring->rd, 0, ring->rd_len);
	for (int i = 0; i < ring->rd_num; ++i) {
		ring->rd[i].iov_base = (char *)ring->mmap_base + (i * ring->flen);
		ring->rd[i].iov_len  = ring->flen;
	}

	ring->rx_rd_size = ring->rx_req.tp_block_size * ring->rx_req.tp_block_nr;
	ring->rx_rd_addr = ring->mmap_base;
	ring->rx_rd_idx  = 0;

	// Tx ring descriptors begin when the Rx ones end
	ring->tx_rd_size = ring->tx_req.tp_block_size * ring->tx_req.tp_block_nr;
	ring->tx_rd_addr = (char *)ring->mmap_base + ring->rx_rd_size;
	ring->tx_rd_idx  = ring->rx_rd_num;

	if ( _verbose )
		click_chatter("[%s] [MMap  Ring] Successfull", ifname.c_str());

	return 0;
}

int
MMapDevice::bind_ring(const String ifname, struct ring *ring)
{
	if ( !has_device(ifname) || !ring ) {
		click_chatter("[%s] [Walk  Ring] Failed to find memory region for this device", ifname.c_str());
		return -1;
	}

	ring->link_layer.sll_family   = PF_PACKET;
	ring->link_layer.sll_protocol = htons(ETH_P_ALL);
	ring->link_layer.sll_ifindex  = if_nametoindex(ifname.c_str());
	ring->link_layer.sll_hatype   = 0;
	ring->link_layer.sll_pkttype  = 0;
	ring->link_layer.sll_halen    = 0;

	int ret = bind(ring->sock_fd, (struct sockaddr *) &ring->link_layer, sizeof(ring->link_layer));
	if ( ret == -1 ) {
		click_chatter("[%s] [Bind  Ring] Could not bind to %d", ifname.c_str(), ring->sock_fd);
		return -1;
	}

	ring->ifname = ifname;

	if ( _verbose )
		click_chatter("[%s] [Bind  Ring] Successfull", ifname.c_str());

	return 0;
}

int
MMapDevice::setup_poll(const String ifname, struct ring *ring, Mode mode)
{
	if ( !has_device(ifname) || !ring ) {
		click_chatter("[%s] [Setup Poll] Failed to identify device", ifname.c_str());
		return -1;
	}

	if ( ring->sock_fd <= 0 ) {
		click_chatter("[%s] [Setup Poll] Cannot setup a poller for a non-existent fd", ifname.c_str());
		return -1;
	}

	if ( (mode != TX_MODE) && (mode != RX_MODE) ) {
		click_chatter("[%s] [Setup Poll] Wrong mode. Choose Tx/Rx", ifname.c_str());
		return -1;
	}

	if ( mode == TX_MODE ) {
		memset(&ring->tx_pfd, 0, sizeof(ring->tx_pfd));
		ring->tx_pfd.fd      = ring->sock_fd;
		ring->tx_pfd.events  = POLLOUT | POLLERR;
		ring->tx_pfd.revents = 0;
	}
	else {
		memset(&ring->rx_pfd, 0, sizeof(ring->rx_pfd));
		ring->rx_pfd.fd      = ring->sock_fd;
		ring->rx_pfd.events  = POLLIN | POLLERR;
		ring->rx_pfd.revents = 0;
	}

	return 0;
}

int
MMapDevice::unmap_ring(const String ifname)
{
	if ( !has_device(ifname) || !_ring_pool[ifname] ) {
		click_chatter("[%s] [MMap  Free] Failed to map memory region", ifname.c_str());
		return -1;
	}

	struct ring *ring = _ring_pool[ifname];

	// Release shared memory
	if ( ring->mmap_base != (void *)-1 ) {
		munmap(ring->mmap_base, ring->mmap_len);
		ring->mmap_base = (void *)-1;
	}

	// Close the socket
	if ( close_socket(ifname, ring) < 0 )
		return -1;

	// Release the ring data structure for this device
	free(_ring_pool[ifname]);

	if ( _verbose )
		click_chatter("[%s] [MMap  Free] Memory released", ifname.c_str());

	return 0;
}

int
MMapDevice::close_socket(const String ifname, struct ring *ring)
{
	if ( !has_device(ifname) || !_ring_pool[ifname] ) {
		click_chatter("[%s] [Close Socket] Failed to find memory region for this device", ifname.c_str());
		return -1;
	}

	if( ring->sock_fd >= 0 ) {
		close(ring->sock_fd);
		ring->sock_fd = -1;

		if ( _verbose )
			click_chatter("[%s] [Close Socket] Done", ifname.c_str());
	}

	return 0;
}

int
MMapDevice::walk_tx_ring_packet(const String ifname, struct ring *ring, Packet *p)
{
	if ( !ring || (ring->ifname != ifname) ) {
		click_chatter("[%s] [Walk Tx Ring] Failed to find memory region for this device",
			ifname.c_str());
		return -1;
	}

	union frame_map ppd;

	if ( !p ) {
		click_chatter("[%s] [Walk Tx Ring] Bad packet", ifname.c_str());
		return -1;
	}
	size_t packet_len = p->length();

	DevInfo *info = _devs.findp(ifname);
	if ( !info ) {
		click_chatter("[%s] [Walk Tx Ring] Device not accessible", ifname.c_str());
		return -1;
	}

	counter_t sent_pkts  = 0;
	counter_t sent_bytes = 0;

	// Where are we in the ring?
	unsigned int frame_num = ring->tx_rd_idx;

	// Poll for more
	poll(&ring->tx_pfd, 1, 0);

	while (	tx_kernel_ready(ring->rd[frame_num].iov_base, ring->version) ) {
		ppd.raw = ring->rd[frame_num].iov_base;

		switch (ring->version) {
			case TPACKET_V1:
				ppd.v1->tp_h.tp_snaplen = packet_len;
				ppd.v1->tp_h.tp_len     = packet_len;

				memcpy(
					(uint8_t *) ppd.raw + TPACKET_HDRLEN - sizeof(struct sockaddr_ll),
					p->data(), packet_len
				);

				/*
				print_frame(
					(uint8_t *) ppd.raw + TPACKET_HDRLEN - sizeof(struct sockaddr_ll),
					packet_len
				);
				*/

				sent_bytes += ppd.v1->tp_h.tp_snaplen;
				break;

			case TPACKET_V2:
				ppd.v2->tp_h.tp_snaplen = packet_len;
				ppd.v2->tp_h.tp_len     = packet_len;

				memcpy(
					(uint8_t *) ppd.raw + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll),
					p->data(), packet_len
				);

				/*
				print_frame(
					(uint8_t *) ppd.raw + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll),
					packet_len
				);
				*/

				sent_bytes += ppd.v2->tp_h.tp_snaplen;
				break;
		}

		sent_pkts++;

		tx_user_ready(ppd.raw, ring->version);

		// Circular logic of the Tx ring buffer.
		// It starts right after the end of the Rx ring buffer.
		if ( frame_num < (ring->rx_rd_num + ring->tx_rd_num -1)) {
			++frame_num;
		}
		else {
			frame_num = ring->rx_rd_num;
		}

		// We transmit only one packet
		break;
	}

	// Transmit the contents of the Tx ring buffers
	int ret = sendto(ring->sock_fd, NULL, 0, 0, NULL, 0);
	if ( ret < 0 ) {
		click_chatter("[%s] [Walk Tx Ring] Failed to transmit the contents of the ring buffer",
			ifname.c_str());
		return -1;
	}

	// Update the statistics
	info->update_tx_info(sent_pkts, sent_bytes);
	ring->tx_rd_idx = frame_num;

	//click_chatter("[%s] [Walk Tx Ring] Sent %d packets (%u bytes)",
	//		ifname.c_str(), sent_pkts, sent_bytes);

	return 0;
}

#if HAVE_BATCH
int
MMapDevice::walk_tx_ring_batch(const String ifname, struct ring *ring, PacketBatch *batch)
{
	union frame_map ppd;

	if ( !batch ) {
		click_chatter("[%s] [Walk Tx Ring] Bad packet batch", ifname.c_str());
		return -1;
	}

	DevInfo *info = _devs.findp(ifname);

	size_t packet_len;
	counter_t sent_pkts  = 0, sent_bytes = 0;
	const unsigned short burst_size = batch->count();

	// Where are we in the ring?
	unsigned int frame_num = ring->tx_rd_idx;
	Packet* current = batch;

//	click_chatter("[%s] [Tx thread] Ring %p to transmit %d packets\n", ifname.c_str(), ring, burst_size);

	while ( (sent_pkts < burst_size) && current ) {

		// Poll for more
		poll(&ring->tx_pfd, 1, 0);

		while (
			tx_kernel_ready(ring->rd[frame_num].iov_base, ring->version) && current
		) {
			ppd.raw = ring->rd[frame_num].iov_base;

			packet_len = current->length();
			//click_chatter("[%s] [Tx thread] Packet %d with length %d bytes\n",
			//		ifname.c_str(), sent_pkts, packet_len);

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

					sent_bytes += ppd.v1->tp_h.tp_snaplen;
					break;

				case TPACKET_V2:
					ppd.v2->tp_h.tp_snaplen = packet_len;
					ppd.v2->tp_h.tp_len     = packet_len;

					memcpy(
						(uint8_t *) ppd.raw + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll),
						current->data(), packet_len
					);

					/*
					print_frame(
						(uint8_t *) ppd.raw + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll),
						packet_len
					);
					*/

					sent_bytes += ppd.v2->tp_h.tp_snaplen;
					break;

				default:
					click_chatter("[%s] [Walk Tx Ring] Bad TPACKET version", ifname.c_str());
					return -1;
			}

			sent_pkts++;
			current = current->next();

			tx_user_ready(ppd.raw, ring->version);

			// Circular logic of the Tx ring buffer.
			// It starts right after the end of the Rx ring buffer.
			if ( frame_num < (ring->rx_rd_num + ring->tx_rd_num -1)) {
				++frame_num;
			}
			else {
				frame_num = ring->rx_rd_num;
			}
		}
	}

	// Transmit the contents of the Tx ring buffer
	int ret = sendto(ring->sock_fd, NULL, 0, 0, NULL, 0);
	if ( ret < 0 ) {
		click_chatter("[%s] [Walk Tx Ring] Failed to transmit the contents of the ring buffer", ifname.c_str());
		return -1;
	}
	info->update_tx_info(sent_pkts, sent_bytes);

	ring->tx_rd_idx = frame_num;

	//click_chatter("[%s] [Walk Tx] Sent %d packets (%u bytes)",
	//	ifname.c_str(), sent_pkts, sent_bytes);

	return sent_pkts;
}
#endif

Packet *
MMapDevice::walk_rx_ring_packet(const String ifname, struct ring *ring)
{
	union frame_map ppd;
	unsigned int frame_num = ring->rx_rd_idx;

	DevInfo *info = _devs.findp(ifname);

	counter_t recv_pkts = 0, recv_bytes = 0;
	WritablePacket *p   = NULL;

	// Ask for packets
	poll(&ring->rx_pfd, 1, 0);

	while ( rx_kernel_ready(ring->rd[frame_num].iov_base, ring->version) ) {
		ppd.raw = ring->rd[frame_num].iov_base;

		uint8_t *frame        = NULL;
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
				return NULL;
		}

		p = Packet::make(Packet::default_headroom, frame, snap_len, 0);
		p->set_packet_type_anno((Packet::PacketType)sll->sll_pkttype);
		p->set_mac_header(p->data());

		//print_frame(p->data(), snap_len);

		rx_user_ready(ppd.raw, ring->version);

		recv_pkts++;
		recv_bytes += snap_len;
		frame_num   = (frame_num + 1) % ring->rx_rd_num;

		// We want only one packet
		break;
	}

	info->update_rx_info(recv_pkts, recv_bytes);

	// Update the index of the Rx ring buffer
	ring->rx_rd_idx = frame_num;

	//click_chatter("[%s] [Walk Rx Ring] Received %d packets (%u bytes)",
	//				ifname.c_str(), recv_pkts, recv_bytes);

	return p;
}

#if HAVE_BATCH
PacketBatch *
MMapDevice::walk_rx_ring_batch(const String ifname, struct ring *ring)
{
	union frame_map ppd;
	unsigned int    frame_num = ring->rx_rd_idx;

	PacketBatch    *head = NULL;
	WritablePacket *last = NULL;

	DevInfo *info = _devs.findp(ifname);

	uint8_t *frame = NULL;
	unsigned int snap_len;
	const struct sockaddr_ll *sll;
	counter_t recv_pkts = 0, recv_bytes = 0;

	// Ask for packets
	poll(&ring->rx_pfd, 1, 0);

	while (
		rx_kernel_ready(ring->rd[frame_num].iov_base, ring->version) &&
		(recv_pkts < info->get_burst_size())
	) {
		ppd.raw = ring->rd[frame_num].iov_base;

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
				return NULL;
		}

		WritablePacket *p = Packet::make(Packet::default_headroom, frame, snap_len, 0);
		p->set_packet_type_anno((Packet::PacketType)sll->sll_pkttype);
		p->set_mac_header(p->data());

		// Aggregate input packets in a batch list
		if ( !head )
			head = PacketBatch::start_head(p);
		else
			last->set_next(p);
		last = p;

		//print_frame(p->data(), snap_len);

		rx_user_ready(ppd.raw, ring->version);

		recv_pkts++;
		recv_bytes += snap_len;
		frame_num   = (frame_num + 1) % ring->rx_rd_num;
	}

	info->update_rx_info(recv_pkts, recv_bytes);

	// Update the index of the Rx ring buffer
	ring->rx_rd_idx = frame_num;

	/*
	click_chatter("[%s] [Walk Rx Ring] Received %d packets (%u bytes)",
				ifname.c_str(), recv_pkts, recv_bytes);
	*/

	// Assimilate batch and return it back to the element
	if ( !head ) {
		return NULL;
	}
	head->make_tail(last, recv_pkts);

	return head;
}
#endif

void
MMapDevice::configure_ring(struct ring *ring, unsigned int blocks)
{
	ring->rx_req.tp_block_size = MMapDevice::BLOCK_SIZE;
	ring->rx_req.tp_frame_size = next_power_of_two(MMapDevice::MTU_SIZE + 128);
	ring->rx_req.tp_block_nr   = blocks;

	// We reserve a number of frames for Tx and Rx
	ring->rx_req.tp_frame_nr =
		(ring->rx_req.tp_block_size / ring->rx_req.tp_frame_size) * ring->rx_req.tp_block_nr;

	// Tx configuration is symmetric with Rx
	ring->tx_req = ring->rx_req;

	// The entire memory region hosts both Tx and Rx buffers
	ring->mmap_len = 	ring->rx_req.tp_block_size * ring->rx_req.tp_block_nr +
						ring->tx_req.tp_block_size * ring->tx_req.tp_block_nr;

	ring->rx_rd_size = ring->rx_req.tp_block_size * ring->rx_req.tp_block_nr;
	ring->tx_rd_size = ring->tx_req.tp_block_size * ring->tx_req.tp_block_nr;
	ring->rx_rd_num  = ring->rx_req.tp_frame_nr;
	ring->tx_rd_num  = ring->tx_req.tp_frame_nr;
	// The total number of ring descriptors is equally divided between Tx and Rx.
	ring->rd_num     = ring->rx_rd_num + ring->tx_rd_num;

	// The length of the frames we can handle. A power of two that aligns with TP.
	ring->flen = ring->rx_req.tp_frame_size;

	if ( _verbose && _debug )
		debug_mmap_layout(&ring->rx_req, &ring->tx_req);
}

int
MMapDevice::set_packet_loss_discard(int sock_fd)
{
	int ret, discard = 1;

	ret = setsockopt(sock_fd, SOL_PACKET, PACKET_LOSS, (void *) &discard, sizeof(discard));
	if ( ret == -1 ) {
		click_chatter("[Set Pkt Loss Discard] Failed to set socket options");
		return -1;
	}

	return 0;
}

int
MMapDevice::tx_kernel_ready(void *base, int version)
{
	switch (version) {
		case TPACKET_V1:
			return _v1_tx_kernel_ready( (struct tpacket_hdr  *)base );
		case TPACKET_V2:
			return _v2_tx_kernel_ready( (struct tpacket2_hdr *)base );
		default:
			click_chatter("[Tx Kernel Ready] Unsupported TPACKET version");
			break;
	}

	return -1;
}

void
MMapDevice::tx_user_ready(void *base, int version)
{
	switch (version) {
		case TPACKET_V1:
			_v1_tx_user_ready( (struct tpacket_hdr  *)base );
			break;
		case TPACKET_V2:
			_v2_tx_user_ready( (struct tpacket2_hdr *)base );
			break;
		default:
			click_chatter("[Tx Kernel Ready] Unsupported TPACKET version");
			exit(-1);
	}
}

int
MMapDevice::_v1_tx_kernel_ready(struct tpacket_hdr *hdr)
{
	return !(hdr->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING));
}

void
MMapDevice::_v1_tx_user_ready(struct tpacket_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_SEND_REQUEST;
	__sync_synchronize();
}

int
MMapDevice::_v2_tx_kernel_ready(struct tpacket2_hdr *hdr)
{
	return !(hdr->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING));
}

void
MMapDevice::_v2_tx_user_ready(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_SEND_REQUEST;
	__sync_synchronize();
}

int
MMapDevice::rx_kernel_ready(void *base, int version)
{
	switch (version) {
		case TPACKET_V1:
			return _v1_rx_kernel_ready( (struct tpacket_hdr  *)base );
		case TPACKET_V2:
			return _v2_rx_kernel_ready( (struct tpacket2_hdr *)base );
		default:
			click_chatter("[Rx Kernel Ready] Unsupported TPACKET version");
			break;
	}

	return -1;
}

void
MMapDevice::rx_user_ready(void *base, int version)
{
	switch (version) {
		case TPACKET_V1:
			_v1_rx_user_ready( (struct tpacket_hdr  *)base );
			break;
		case TPACKET_V2:
			_v2_rx_user_ready( (struct tpacket2_hdr *)base );
			break;
		default:
			click_chatter("[Rx User Ready] Unsupported TPACKET version");
			exit(-1);
	}
}

int
MMapDevice::_v1_rx_kernel_ready(struct tpacket_hdr *hdr)
{
	return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);
}

void
MMapDevice::_v1_rx_user_ready(struct tpacket_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_KERNEL;
	__sync_synchronize();
}

int
MMapDevice::_v2_rx_kernel_ready(struct tpacket2_hdr *hdr)
{
	return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);
}

void
MMapDevice::_v2_rx_user_ready(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_KERNEL;
	__sync_synchronize();
}

int
MMapDevice::test_kernel_bit_width(void)
{
	char in[512], *ptr;
	int num = 0, fd;
	ssize_t ret;

	fd = open("/proc/kallsyms", O_RDONLY);
	if (fd == -1) {
		click_chatter("[Test Kernel Conf] Failed to access /proc");
		exit(1);
	}

	ret = read(fd, in, sizeof(in));
	if (ret <= 0) {
		click_chatter("[Test Kernel Conf] Failed to access /proc");
		exit(1);
	}
	close(fd);

	ptr = in;
	while( !isspace(*ptr) ) {
		num++;
		ptr++;
	}

	return num * 4;
}

int
MMapDevice::test_user_bit_width(void)
{
	return __WORDSIZE;
}

void
MMapDevice::print_frame(void *frame, size_t len)
{
	struct ethhdr *eth = (struct ethhdr *)frame;

	if ( len < sizeof(struct ethhdr) ) {
		click_chatter("[Test Payload] Frame too small: %zu bytes!", len);
		return;
	}

	if ( eth->h_proto != htons(ETH_P_IP) ) {
		click_chatter("[Test Payload] Wrong ethernet type: 0x%x!\n", ntohs(eth->h_proto));
		return;
	}

	struct iphdr *ip = (struct iphdr *)  ((char *) eth + ETH_HLEN);

	struct sockaddr_in ss, sd;
	char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];

	memset(&ss, 0, sizeof(ss));
	ss.sin_family = PF_INET;
	ss.sin_addr.s_addr = ip->saddr;
	getnameinfo((struct sockaddr *) &ss, sizeof(ss),
			    sbuff, sizeof(sbuff), NULL, 0, NI_NUMERICHOST);

	memset(&sd, 0, sizeof(sd));
	sd.sin_family = PF_INET;
	sd.sin_addr.s_addr = ip->daddr;
	getnameinfo((struct sockaddr *) &sd, sizeof(sd),
		    dbuff, sizeof(dbuff), NULL, 0, NI_NUMERICHOST);

	if ( ip->protocol == IPPROTO_UDP ) {
		struct udphdr *udp = (struct udphdr *)((char *) ip + sizeof(struct iphdr));
		click_chatter("%s.%d > %s.%d, UDP", sbuff, ntohs(udp->source), dbuff, ntohs(udp->dest));
	}
	else if ( ip->protocol == IPPROTO_TCP ) {
		struct tcphdr *tcp = (struct tcphdr *)((char *) ip + sizeof(struct iphdr));
		click_chatter("%s.%d > %s.%d, TCP", sbuff, ntohs(tcp->source), dbuff, ntohs(tcp->dest));
	}
	else {
		click_chatter("%s > %s, IP", sbuff, dbuff);
	}
}

void
MMapDevice::debug_tpacket_frame(const void *base)
{
	if ( !base )
		if ( _verbose )
			click_chatter("[TPACKET Info] Unable to display information");

	click_chatter("[TPACKET Info] Buffer base addr %p", base);

	const struct tpacket2_hdr *header = (const struct tpacket2_hdr *)base;
	click_chatter("[TPACKET Info] tpacket2_header: ");
	click_chatter("\ttp_status   : 0x%02x", header->tp_status);
	click_chatter("\ttp_len      : %d", header->tp_len);
	click_chatter("\ttp_snaplen  : %d", header->tp_snaplen);
	click_chatter("\ttp_mac      : %d", header->tp_mac);
	click_chatter("\ttp_net      : %d", header->tp_net);
	click_chatter("\ttp_sec      : %d", header->tp_sec);
	click_chatter("\ttp_nsec     : %d", header->tp_nsec);
	click_chatter("\ttp_vlan_tci : 0x%04x", header->tp_vlan_tci);

	const struct sockaddr_ll *sll =
		(const struct sockaddr_ll *) (base + TPACKET_ALIGN(sizeof(struct tpacket2_hdr)));
	click_chatter("[TPACKET Info] sockaddr_ll: ");
	click_chatter("\t\tsll_family   : 0x%02x", sll->sll_family);
	click_chatter("\t\tsll_protocol : 0x%04x", sll->sll_protocol);
	click_chatter("\t\tsll_ifindex  : %d", sll->sll_ifindex);
	click_chatter("\t\tsll_hatype   : %d", sll->sll_hatype);
	click_chatter("\t\tsll_pkttype  : %d", sll->sll_pkttype);
	click_chatter("\t\tsll_halen    : %d", sll->sll_halen);
	click_chatter("\t\tsll_addr[8]  : %02x:%02x:%02x:%02x:%02x:%02x",
		sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
		sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]
	);
}

void
MMapDevice::debug_mmap_layout(
		const struct tpacket_req *rx_packet_req,
		const struct tpacket_req *tx_packet_req
){
	if ( !rx_packet_req || !tx_packet_req )
		if ( _verbose )
			click_chatter("[MMap Layout] Unable to display information");

	click_chatter("[MMap Layout] TPACKET_ALIGNMENT = %d", TPACKET_ALIGNMENT);
	click_chatter("[MMap Layout] TPACKET2_HDRLEN   = %d", TPACKET2_HDRLEN);
	click_chatter("[MMap Layout] Sizeof(struct sockaddr_ll) = %d", sizeof(struct sockaddr_ll));
	click_chatter("[MMap Layout] Rx packet req:");
	click_chatter("\t\ttp_block_size = %d", rx_packet_req->tp_block_size);
	click_chatter("\t\ttp_block_nr   = %d", rx_packet_req->tp_block_nr);
	click_chatter("\t\ttp_frame_size = %d", rx_packet_req->tp_frame_size);
	click_chatter("\t\ttp_frame_nr   = %d", rx_packet_req->tp_frame_nr);
	click_chatter("[MMap Layout] Tx packet req:");
	click_chatter("\t\ttp_block_size = %d", tx_packet_req->tp_block_size);
	click_chatter("\t\ttp_block_nr   = %d", tx_packet_req->tp_block_nr);
	click_chatter("\t\ttp_frame_size = %d", tx_packet_req->tp_frame_size);
	click_chatter("\t\ttp_frame_nr   = %d", tx_packet_req->tp_frame_nr);
}

/*
int
MMapDevice::walk_threads(Mode mode, struct ring *ring)
{
	//
	// Start thread that sends data to the circular buffer
	//
	//
	pthread_t t_send;
	pthread_attr_t t_attr_send;
	struct sched_param para_send;
	pthread_attr_init(&t_attr_send);
	pthread_attr_setschedpolicy(&t_attr_send,SCHED_RR);
	para_send.sched_priority=20;
	pthread_attr_setschedparam(&t_attr_send, &para_send);

	if ( pthread_create(&t_send, &t_attr_send, walk_tx, (void *)ring) != 0 ) {
		perror("pthread_create()");
		abort();
	}
	//

	//
	// Start thread that receives data from circular buffer
	//
	//
	pthread_t t_recv;
	pthread_attr_t t_attr_recv;
	struct sched_param para_recv;
	pthread_attr_init(&t_attr_recv);
	pthread_attr_setschedpolicy(&t_attr_recv,SCHED_RR);
	para_recv.sched_priority=20;
	pthread_attr_setschedparam(&t_attr_recv, &para_recv);

	if ( pthread_create(&t_recv, &t_attr_recv, walk_rx, (void *)ring) != 0 ) {
		perror("pthread_create()");
		abort();
	}
	//

	// Wait for the mto finish
	//
	pthread_join (t_send, NULL);
	click_chatter("Tx thread joined\n");
	pthread_join (t_recv, NULL);
	click_chatter("Rx thread joined\n");
	//
}
*/

CLICK_ENDDECLS
