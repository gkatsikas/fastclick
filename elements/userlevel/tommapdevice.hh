#ifndef CLICK_TOMMAPDEVICE_USERLEVEL_HH
#define CLICK_TOMMAPDEVICE_USERLEVEL_HH

#include <click/string.hh>
#include <click/batchelement.hh>

#include "elements/userlevel/frommmapdevice.hh"

CLICK_DECLS

/*
=title ToMMapDevice.u
=c
ToMMapDevice(DEVNAME [, I<keywords>])
=s netdevices
sends packets to network device (user-level)
=d

This manual page describes the user-level version of the ToMMapDevice element.
Full-push element with an internal queue and the Tx ring buffers mapped to
user-space using the TPACKET API.

Keyword arguments are:

=over 8

=item IQUEUE

Integer. Size of the internal queue, i.e. number of packets that we can buffer
before pushing them to the ring buffers. If IQUEUE is bigger than BURST,
some packets could be buffered in the internal queue when the output ring is
full. Defaults to 1024.

=item BURST

Integer. Number of packets to batch before sending them out. A bigger BURST
leads to more latency, but a better throughput. The default value of 32.
Prefer to set the TIMEOUT parameter to 0 if the throughput is low as it will
maintain performance.

=item BLOCKING

Boolean.  If true, when there is no more space in the output device ring, and
the IQUEUE is full, we'll block until some packet could be sent. If false the
packet will be dropped. Defaults to true.

=item TIMEOUT

Integer. Set a timeout to flush the internal queue. It is useful under low
throughput as it could take a long time before reaching BURST packet in the
internal queue. The timeout is expressed in milliseconds. Setting the timer to
0 is not a bad idea as it will schedule after the source element (such as a
FromMMapDevice) will have finished its burst, or all incoming packets. This
would therefore ensure that a flush is done right after all packets have been
processed by the Click pipeline. Setting a negative value disables the timer,
this is generally acceptable if the thoughput of this element rarely drops
below 32000 pps (~50 Mbps with maximal size packets) with a BURST of 32, as the
internal queue will wait on average 1 ms before containing 32 packets. Defaults
to 0 (immediate flush).

=item VERBOSE

Boolean. If true, displays log messages from the MMap library. Defaults to false.

=item DEBUG

Boolean. If true, displays debugging information from the MMap library. Defaults to false.

=back

This element is only available at user level.

=e

  FromMMapDevice(eth0) -> Print -> ToMMapDevice(eth0);

=n

Packets sent via ToMMapDevice should already have a link-level
header prepended. This means that ARP processing,
for example, must already have been done.

The L<FromMMapDevice(n)> element's OUTBOUND keyword argument determines whether
FromMMapDevice receives packets sent by a ToMMapDevice element for the same
device.

Packets that are written successfully are sent on output 0, if it exists.
Packets that fail to be written are pushed out output 1, if it exists.

=h sent read-only

Returns the number of packets sent by the device.

=h dropped read-only

Returns the number of packets dropped by the internal queue (due to congestion).

=h avg_tx_bs read-only

Returns the average number of packets transmitted at once (batch-style).

=a
FromMMapDevice */

class ToMMapDevice : public BatchElement {

	public:
		ToMMapDevice () CLICK_COLD;
		~ToMMapDevice() CLICK_COLD;

		const char *class_name() const	{ return "ToMMapDevice"; }
		const char *port_count() const	{ return PORTS_1_0; }
		const char *processing() const	{ return PUSH; }
		int    configure_phase() const 	{ return KernelFilter::CONFIGURE_PHASE_TODEVICE; }

		int  configure     (Vector<String> &, ErrorHandler *) 	CLICK_COLD;
		int  initialize    (ErrorHandler *) 			CLICK_COLD;
		void cleanup       (CleanupStage) 			CLICK_COLD;
		void add_handlers  () 					CLICK_COLD;

		String ifname() const	{ return _ifname; }
		int    fd()     const	{ return _fd; }

		void push_packet(int port, Packet      *p);
	#if HAVE_BATCH
		void push_batch (int port, PacketBatch *batch);
	#endif


	protected:

		class TXInternalQueue {
			public:
				TXInternalQueue() : pkts(0), index(0), nr_pending(0) { }

				// Array of Click packets
				Packet **pkts;
				// Index of the first valid packet in the packets array
				unsigned int index;
				// Number of valid packets awaiting to be sent after index
				unsigned int nr_pending;

				// Timer to limit time a batch will take to be completed
				Timer timeout;
		} __attribute__((aligned(64)));

		inline void set_flush_timer       (TXInternalQueue &iqueue);
		void flush_internal_tx_queue      (TXInternalQueue &iqueue);
	#if HAVE_BATCH
		void flush_internal_tx_queue_batch(TXInternalQueue &iqueue);
	#endif

		// Internal queue to store packets to be emitted
		TXInternalQueue _iqueue;
		int             _internal_tx_queue_size;

		String          _ifname;
		int             _fd;
		struct ring    *_ring;

		Task            _task;

		bool            _blocking;
		int             _burst_size;
		int             _timeout;
		bool            _congestion_warning_printed;
		bool            _verbose;
		bool            _debug;

		counter_t       _n_sent;
		counter_t       _n_dropped;
		counter_t       _send_calls;

	#if HAVE_BATCH
		// Calculate some statistics when in batch mode
		int  _inc_batch_size;
	#endif

		FromMMapDevice *find_fromdevice() const;

		int send_packet(Packet      *p);
	#if HAVE_BATCH
		int send_batch (PacketBatch *batch);
	#endif

		enum { h_sent, h_dropped, h_avg_tx_bs };
		static String read_handler(Element*, void*) CLICK_COLD;
};

CLICK_ENDDECLS

#endif
