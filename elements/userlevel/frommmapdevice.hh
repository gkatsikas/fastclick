#ifndef CLICK_FROMMMAPDEVICE_USERLEVEL_HH
#define CLICK_FROMMMAPDEVICE_USERLEVEL_HH
#include <click/batchelement.hh>
#include <click/notifier.hh>
#include <click/mmapdevice.hh>

#include "queuedevice.hh"

CLICK_DECLS

/*
=title FromMMapDevice.u

=c

FromMMapDevice(DEVNAME [, I<keywords> SNIFFER, PROMISC, FORCE_IP, etc.])

=s netdevices

Memory-mapping of packets from a Linux-based network device to the user-space.

=d

This manual page describes the user-level version of the FromMMapDevice
element.

Reads packets from the kernel that were received on the network controller
named DEVNAME.

User-level FromMMapDevice behaves like a packet sniffer by default. Packets
emitted by FromMMapDevice are also received and processed by the kernel. Thus, it
doesn't usually make sense to run a router with user-level Click, since each
packet will get processed twice (once by Click, once by the kernel). Install
firewalling rules in your kernel if you want to prevent this, for instance
using the KernelFilter element or FromMMapDevice's SNIFFER false argument.

Under Linux, a FromMMapDevice element will not receive packets sent by a
ToDevice element for the same device. Under other operating systems, your
mileage may vary.

Sets the packet type annotation appropriately. Also sets the timestamp
annotation to the time the kernel reports that the packet was received.

Keyword arguments are:

=over 8

=item DEVNAME


=item MAXTHREADS

Maximal number of threads that this element will take to read packets from
the input queue. If unset (or negative) all threads not pinned with a
ThreadScheduler element will be shared among FromDPDKDevice elements and
other input elements supporting multiqueue (extending QueueDevice)

=item THREADOFFSET

Specify which Click thread will handle this element. If multiple
j threads are used, threads with id THREADOFFSET+j will be used. Default is
to share the threads available on the device's NUMA node equally.

=item MINQUEUE
Minimum number of hardware queue of the devices to use. Multiple queues
allows to load balance the traffic on multiple thread using RSS.
Default is 1.

=item MAXQUEUES
Maximum number of hardware queue to use. Default is 128.

=item BURST

Integer. Maximum number of packets to read per scheduling. Defaults to 1.

=item TIMESTAMP

Boolean. If false, then do not timestamp packets. Defaults to true.

=back

=e

  FromMMapDevice(eth0) -> ...

=n

FromMMapDevice sets packets' extra length annotations as appropriate.

=h count read-only

Returns the number of packets read by the device.

=h reset_counts write-only

Resets "count" to zero.

=h kernel_drops read-only

Returns the number of packets dropped by the kernel, probably due to memory
constraints, before FromMMapDevice could get them. This may be an integer; the
notation C<"<I<d>">, meaning at most C<I<d>> drops; or C<"??">, meaning the
number of drops is not known.

=a ToMMapDevice.u */

class FromMMapDevice : public QueueDevice {
	public:
		FromMMapDevice()  CLICK_COLD;
		~FromMMapDevice() CLICK_COLD;

		const char *class_name() const	{ return "FromMMapDevice"; }
		const char *port_count() const	{ return "0/1-2"; }
		const char *processing() const	{ return PUSH; }

		enum { default_snaplen = 2046 };
		int configure_phase() const {
			return CONFIGURE_PHASE_PRIVILEGED - 5;
		}

		int configure    (Vector<String> &, ErrorHandler *) 	CLICK_COLD;
		int initialize   (ErrorHandler *)			CLICK_COLD;
		void cleanup     (CleanupStage)				CLICK_COLD;
		void add_handlers()					CLICK_COLD;

		inline String ifname() const    { return _ifname; }
		inline int fd() const           { return _ring->sock_fd; }

		void selected(int fd, int mask);
		bool run_task(Task *);
		unsigned int receive_packets();
		void walk_rx_ring_batch(const String ifname, struct ring *ring);

		int setup_device(
			const String ifname, struct ring **ring, ErrorHandler *errh
		);

		inline struct ring *get_fromdevice_mmap(const String ifname, ErrorHandler *errh) {
			if ( ifname != _ifname ) return NULL;
			if ( !_ring ) {
				setup_device(ifname, &_ring, errh);
			}
			return _ring;
		};
		inline int get_fromdevice_fd(const String ifname, bool *existed, ErrorHandler *errh) {
			if ( !_ring || _ring->sock_fd <= 0 ) {
				int fd = setup_device(_ifname, &_ring, errh);
				if ( fd <= 0 ) {
					return -1;
				}
				*existed = false;
				return fd;
			}
			*existed = true;
			return _ring->sock_fd;
		};

	private:
		Task _task;
		bool _numa;

		String       _ifname;
		struct ring *_ring;
		unsigned     _nb_blocks;

	#if HAVE_INT64_TYPES
		typedef uint64_t counter_t;
	#else
		typedef uint32_t counter_t;
	#endif
		counter_t _bytes_total;
		counter_t _packets_total;

		unsigned int _burst_size;

		static String read_handler(Element*, void*) CLICK_COLD;
		static int write_handler  (const String&, Element*, void*, ErrorHandler*) CLICK_COLD;
};

CLICK_ENDDECLS
#endif
