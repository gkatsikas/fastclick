#ifndef CLICK_FROMBATCHDEVICE_USERLEVEL_HH
#define CLICK_FROMBATCHDEVICE_USERLEVEL_HH

#include <click/batchelement.hh>

#include "elements/userlevel/kernelfilter.hh"

CLICK_DECLS

/*
=title FromBatchDevice.u

=c

FromBatchDevice(DEVNAME [, I<keywords> SNIFFER, PROMISC, FORCE_IP, etc.])

=s netdevices

reads packets from a Linux-based network device (user-level)

=d

This manual page describes the user-level FromBatchDevice element.
Reads packets from the kernel that were received on the network controller
named DEVNAME. It operates on both normal and batch mode by pushing packets
or batches of packets to the next element respectively.

FromBatchDevice behaves like a packet sniffer by default. Packets
emitted by FromBatchDevice are also received and processed by the kernel.
Thus, it doesn't usually make sense to run a router with user-level Click,
since each packet will get processed twice (once by Click, once by the kernel).
Install firewalling rules in your kernel if you want to prevent this, for instance
using the KernelFilter element or FromBatchDevice's SNIFFER false argument.

Sets the packet type annotation appropriately. Also sets the timestamp
annotation to the time the kernel reports that the packet was received.

Keyword arguments are:

=over 8

=item DEVNAME

String. The name of the interface where we receive packets from.

=item SNIFFER

Boolean.  Specifies whether FromBatchDevice should run in sniffer mode.  In
non-sniffer mode, FromBatchDevice installs KernelFilter filtering rules to block
the kernel from handling any packets arriving on device DEVNAME.  Default is
true (sniffer mode).

=item PROMISC

Boolean.  FromBatchDevice puts the device in promiscuous mode if PROMISC is true.
The default is false.

=item SNAPLEN

Unsigned.  On some systems, packets larger than SNAPLEN will be truncated.
Defaults to 2046.

=item FORCE_IP

Boolean. If true, then output only IP packets. (Any link-level header remains,
but the IP header annotation has been set appropriately.) Default is false.

=item OUTBOUND

Boolean. If true, then emit packets that the kernel sends to the given
interface, as well as packets that the kernel receives from it. Default is
false.

=item PROTOCOL

Integer. If set and nonzero, then only emit packets with this link-level
protocol. Default is 0.

=item HEADROOM

Integer. Amount of bytes of headroom to leave before the packet data. Defaults
to roughly 28.

=item BURST

Integer. Maximum number of packets to read per scheduling. Defaults to 1.

=item TIMESTAMP

Boolean. If false, then do not timestamp packets. Defaults to true.

=back

=e

  FromBatchDevice(eth0) -> ...

=n

FromBatchDevice sets packets' extra length annotations as appropriate.

=h count read-only

Returns the number of packets read by the device.

=h kernel_drops read-only

Returns the number of packets dropped by the kernel, probably due to memory
constraints, before FromBatchDevice could get them. This may be an integer; the
notation C<"<I<d>">, meaning at most C<I<d>> drops; or C<"??">, meaning the
number of drops is not known.

=h avg_rx_bs read-only

Returns the average number of packets received at once (batch-style).

=h avg_proc_bs read-only

Returns the average number of packets pushed to the next element at once (batch-style).

=h reset_counts write-only

Resets "count", "avg_proc_bs", "avg_rx_bs" to zero.

=a ToBatchDevice.u */

#if HAVE_INT64_TYPES
	typedef uint64_t counter_t;
#else
	typedef uint32_t counter_t;
#endif

const short BATCHDEV_MIN_PREF_BATCH_SIZE = 8;
const short BATCHDEV_DEF_PREF_BATCH_SIZE = 28;
const short BATCHDEV_MAX_PREF_BATCH_SIZE = 32;

class FromBatchDevice : public BatchElement {
	public:

		FromBatchDevice () CLICK_COLD;
		~FromBatchDevice() CLICK_COLD;

		const char *class_name() const	{ return "FromBatchDevice"; }
		const char *port_count() const	{ return "0/1-2"; }
		const char *processing() const	{ return PUSH; }

		enum { default_snaplen = 2046 };
		int    configure_phase() const	{ return KernelFilter::CONFIGURE_PHASE_FROMDEVICE; }

		int  configure   (Vector<String> &, ErrorHandler *) 	CLICK_COLD;
		int  initialize  (ErrorHandler *) 			CLICK_COLD;
		void cleanup     (CleanupStage) 			CLICK_COLD;
		void add_handlers() 					CLICK_COLD;

		inline String ifname() const	{ return _ifname; }
		inline int        fd() const	{ return _fd; }

		void       selected (int fd, int mask);

		static int open_packet_socket(String, ErrorHandler *);
		static int set_promiscuous   (int, String, bool);
		void       kernel_drops      (bool &known, int &max_drops) const;

	private:

		String    _ifname;
		int       _fd;

		bool      _force_ip;
		int       _burst_size;
		int       _datalink;

		bool      _sniffer     : 1;
		bool      _promisc     : 1;
		bool      _outbound    : 1;
		bool      _timestamp   : 1;
		int       _was_promisc : 2;
		int       _snaplen;
		uint16_t  _protocol;
		unsigned  _headroom;
		bool      _verbose;

		counter_t _n_recv;

		// Data structures necessary to batch the Rx syscalls
		// We pre-allocate an array of Click packets that point
		// to I/O vector data structures, filled by the NIC with
		// a single syscall.
		WritablePacket **_pkts;
		struct mmsghdr  *_msgs;
		struct iovec    *_iovecs;

		static String read_handler (Element*, void*) CLICK_COLD;
		static int    write_handler(
			const String &, Element *, void *, ErrorHandler *
		) CLICK_COLD;
};

CLICK_ENDDECLS
#endif
