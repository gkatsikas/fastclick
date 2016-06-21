#ifndef CLICK_TOBATCHDEVICE_USERLEVEL_HH
#define CLICK_TOBATCHDEVICE_USERLEVEL_HH

#include <click/batchelement.hh>
#include <click/standard/storage.hh>
#include <click/string.hh>

#include "elements/userlevel/frombatchdevice.hh"

CLICK_DECLS

/*
=title ToBatchDevice.u

=c

ToBatchDevice(DEVNAME [, I<keywords>])

=s netdevices

sends packets to a Linux-based network device (user-level) in batch mode

=d

This manual page describes the user-level ToBatchDevice element.
Sends packets out the named device using a full-push model with an internal queue.
Keyword arguments are:

=over 8

=item DEVNAME

String. The name of the interface where we send the packets.

=item BURST

Integer. Maximum number of packets to pull per scheduling. Defaults to 1.

=back

This element is only available at user level.

=n

Packets sent via ToBatchDevice should already have a link-level
header prepended. This means that ARP processing,
for example, must already have been done.

The L<FromBatchDevice(n)> element's OUTBOUND keyword argument determines whether
FromBatchDevice receives packets sent by a ToBatchDevice element for the same
device.

No putput ports.

=a
FromBatchDevice.u
*/

class ToBatchDevice : public BatchElement {
	public:

		ToBatchDevice()  CLICK_COLD;
		~ToBatchDevice() CLICK_COLD;

		const char *class_name() const { return "ToBatchDevice"; }
		const char *port_count() const { return PORTS_1_0; }
		const char *processing() const { return PUSH; }

		int    configure_phase() const	{ return CONFIGURE_PHASE_PRIVILEGED; }

		int configure    (Vector<String> &, ErrorHandler *) 	CLICK_COLD;
		int initialize   (ErrorHandler *) 			CLICK_COLD;
		void cleanup     (CleanupStage) 			CLICK_COLD;
		void add_handlers() 					CLICK_COLD;

		String ifname() const 	{ return _ifname; }
		int        fd() const 	{ return _fd; }

		void push_packet(int port, Packet *);
	#if HAVE_BATCH
		void push_batch (int port, PacketBatch *);
	#endif

	protected:

		class TXInternalQueue {
			public:
				TXInternalQueue() : pkts(0), index(0), nr_pending(0) { }

				// Array of DPDK Buffers
				Packet **pkts;
				// Index of the first valid packet in the packets array
				unsigned int index;
				// Number of valid packets awaiting to be sent after index
				unsigned int nr_pending;

				// Timer to limit time a batch will take to be completed
				Timer timeout;
		} __attribute__((aligned(64)));

		inline void set_flush_timer (TXInternalQueue &iqueue);
		void flush_internal_tx_queue(TXInternalQueue &iqueue);

		// Internal queue to store packets to be emitted
		// No need to use a Queue element anymore
		TXInternalQueue _iqueue;
		unsigned int    _internal_tx_queue_size;

		String          _ifname;
		int             _fd;
		bool            _my_fd;

		counter_t       _n_sent;
		counter_t       _n_dropped;

		int             _burst_size;
		short           _timeout;
		bool            _blocking;
		bool            _congestion_warning_printed;

		FromBatchDevice *find_fromdevice() const;
		int send_packet(Packet *p);

		static String read_handler(Element *e, void *thunk) CLICK_COLD;
};

CLICK_ENDDECLS
#endif
