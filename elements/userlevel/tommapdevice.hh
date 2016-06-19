#ifndef CLICK_TOMMAPDEVICE_USERLEVEL_HH
#define CLICK_TOMMAPDEVICE_USERLEVEL_HH
#include <click/batchelement.hh>
#include <click/string.hh>
#include <click/sync.hh>

#include "elements/userlevel/frommmapdevice.hh"

CLICK_DECLS

/*
 * =title ToMMapDevice.u
 * =c
 * ToMMapDevice(DEVNAME [, I<keywords>])
 * =s netdevices
 * sends packets to network device (user-level)
 * =d
 *
 * This manual page describes the user-level version of the ToMMapDevice element.
 * Pulls packets in batch-style and sends them out using the TPACKET API.
 *
 * Keyword arguments are:
 *
 * =over 8
 *
 * =item BURST
 *
 * Integer. Maximum number of packets to pull per scheduling. Defaults to 1.
 *
 * =back
 *
 * This element is only available at user level.
 *
 * =n
 *
 * Packets sent via ToMMapDevice should already have a link-level
 * header prepended. This means that ARP processing,
 * for example, must already have been done.
 *
 * The L<FromMMapDevice(n)> element's OUTBOUND keyword argument determines whether
 * FromMMapDevice receives packets sent by a ToMMapDevice element for the same
 * device.
 *
 * Packets that are written successfully are sent on output 0, if it exists.
 * Packets that fail to be written are pushed out output 1, if it exists.
 *
 * =a
 * FromMMapDevice */

class ToMMapDevice : public QueueDevice { public:

	ToMMapDevice()  CLICK_COLD;
	~ToMMapDevice() CLICK_COLD;

	const char *class_name() const	{ return "ToMMapDevice"; }
	const char *port_count() const	{ return PORTS_1_0; }
	const char *processing() const	{ return PUSH; }
	int    configure_phase() const 	{ return CONFIGURE_PHASE_PRIVILEGED; }
//	bool can_live_reconfigure() const { return false; }

	int  configure     (Vector<String> &, ErrorHandler *) 	CLICK_COLD;
	int  initialize    (ErrorHandler *) 			CLICK_COLD;
	void cleanup       (CleanupStage) 			CLICK_COLD;

	void add_handlers() CLICK_COLD;

	String ifname() const	{ return _ifname; }
	int    fd()     const	{ return _fd; }

	void run_timer(Timer *);
	void push_packet(int port, Packet      *p);
#if HAVE_BATCH
	void push_batch (int port, PacketBatch *batch);
#endif
	int  walk_tx_ring_batch(const String ifname, struct ring *ring, PacketBatch *b);

	static void * task_send(void *arg);

  protected:

	String       _ifname;
	int          _fd;
	struct ring *_ring;

	Packet      *_q;
#if HAVE_BATCH
	PacketBatch *_q_batch;
#endif

	int          _burst;
	unsigned int _iqueue_size;
	bool         _blocking;
	int          _burst_size;
	int          _timeout;
	bool         _congestion_warning_printed;

	class InternalQueue {
		public:
			InternalQueue() : pkts(0), index(0), nr_pending(0) { }

			// Array of Click packets
			Packet **pkts;
			// Index of the first valid packet in the pkts array
			unsigned int index;
			// Number of valid packets awaiting to be sent after index
			unsigned int nr_pending;

			// Timer to limit time a batch will take to be completed
			Timer timeout;
	} __attribute__((aligned(64)));

	per_thread<InternalQueue> _iqueues;
	void flush_internal_queue(InternalQueue &);

	enum { h_debug, h_signal, h_pulls, h_q };
	FromMMapDevice *find_fromdevice() const;

	counter_t _bytes_total;
	counter_t _packets_total;
	counter_t _packets_dropped;

	int send_packet(Packet      *p);
#if HAVE_BATCH
	int send_batch (PacketBatch *batch);
#endif

	static String read_handler(Element*, void*) CLICK_COLD;
};

CLICK_ENDDECLS

#endif
