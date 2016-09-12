#ifndef CLICK_TOBATCHDEVICE_USERLEVEL_HH
#define CLICK_TOBATCHDEVICE_USERLEVEL_HH

#include <click/string.hh>
#include <click/batchelement.hh>

#include "elements/userlevel/frombatchdevice.hh"

CLICK_DECLS

/*
=title ToBatchDevice.u

=c

ToBatchDevice(DEVNAME [, I<keywords>])

=s netdevices

sends packets to a Linux-based network device (user-level) in batch mode.

=d

This manual page describes the user-level ToBatchDevice element.
Sends packets out the named device using a full-push model with an internal queue
and batching of system calls.
Keyword arguments are:

=over 8

=item DEVNAME

String. The name of the interface where we send the packets.

=item IQUEUE

Integer.  Size of the internal queue, i.e. number of packets that we can buffer
before pushing them to the NIC. If IQUEUE is bigger than BURST,
some packets could be buffered in the internal queue when the output buffer is
full. Defaults to 1024.

=item BURST

Integer. Maximum number of packets to pull per scheduling. Defaults to 1.
Prefer to set the TIMEOUT parameter to 0 if the throughput is low as it
will maintain performance.

=item BLOCKING

Boolean.  If true, when there is no more space in the output device ring, and
the IQUEUE is full, we'll block until some packet could be sent. If false the
packet will be dropped. Defaults to true.

=item TIMEOUT

Integer.  Set a timeout to flush the internal queue. It is useful under low
throughput as it could take a long time before reaching BURST packet in the
internal queue. The timeout is expressed in milliseconds. Setting the timer to
0 is not a bad idea as it will schedule after the source element (such as a
FromBatchDevice) will have finished its burst, or all incoming packets. This
would therefore ensure that a flush is done right after all packets have been
processed by the Click pipeline. Setting a negative value disable the timer,
this is generally acceptable if the thoughput of this element rarely drops
below 32000 pps (~50 Mbps with maximal size packets) with a BURST of 32, as the
internal queue will wait on average 1 ms before containing a burst again. Defaults
to 0 (immediate flush).

=back

This element is only available at user level.

=e

  FromBatchDevice(eth0) -> Print -> ToBatchDevice(eth0)

=n

Packets sent via ToBatchDevice should already have a link-level
header prepended. This means that ARP processing,
for example, must already have been done.

The L<FromBatchDevice(n)> element's OUTBOUND keyword argument determines whether
FromBatchDevice receives packets sent by a ToBatchDevice element for the same
device.

No putput ports.

=h sent read-only

Returns the number of packets sent by the device.

=h dropped read-only

Returns the number of packets dropped by the internal queue (due to congestion).

=h avg_tx_bs read-only

Returns the average number of packets transmitted at once (batch-style).

=a
FromBatchDevice.u
*/

class ToBatchDevice : public BatchElement {
	public:

		ToBatchDevice () CLICK_COLD;
		~ToBatchDevice() CLICK_COLD;

		const char *class_name() const { return "ToBatchDevice"; }
		const char *port_count() const { return PORTS_1_0; }
		const char *processing() const { return PUSH; }
		int    configure_phase() const { return KernelFilter::CONFIGURE_PHASE_TODEVICE; }

		int  configure   (Vector<String> &, ErrorHandler *) 	CLICK_COLD;
		int  initialize  (ErrorHandler *) 			CLICK_COLD;
		void cleanup     (CleanupStage) 			CLICK_COLD;
		void add_handlers() 					CLICK_COLD;

		String ifname() const 	{ return _ifname; }
		int        fd() const 	{ return _fd; }

		void push_packet(int port, Packet      *);
	#if HAVE_BATCH
		void push_batch (int port, PacketBatch *);
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
		// No need to use a Queue element anymore
		TXInternalQueue _iqueue;
		int             _internal_tx_queue_size;

		Task            _task;

		String          _ifname;
		int             _fd;
		bool            _my_fd;

		counter_t       _n_sent;
		counter_t       _n_dropped;

		int             _burst_size;
		short           _timeout;
		bool            _blocking;
		bool            _congestion_warning_printed;
		bool            _verbose;

	#if HAVE_BATCH
		// Data structures necessary to batch the Tx syscalls
		// We an I/O vector data structure with a batch of Click
		// packets and emit them all with a single syscall.
		struct mmsghdr  *_msgs;
		struct iovec    *_iovecs;
	#endif

		FromBatchDevice *find_fromdevice() const;
		int find_fromdevice_core() const;
		int send_packet(Packet *p);

		enum { h_sent, h_dropped };
		static String read_handler(Element *e, void *thunk) CLICK_COLD;
};

CLICK_ENDDECLS
#endif
