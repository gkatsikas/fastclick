#ifndef CLICK_FROMMMAPDEVICE_USERLEVEL_HH
#define CLICK_FROMMMAPDEVICE_USERLEVEL_HH

#include <click/batchelement.hh>
#include <click/mmapdevice.hh>

#include "elements/userlevel/kernelfilter.hh"

CLICK_DECLS

/*
=title FromMMapDevice.u

=c

FromMMapDevice(DEVNAME [, I<keywords> BURST, VERBOSE, DEBUG])

=s netdevices

Memory-mapping of packets from a Linux-based network device to the user-space.

=d

This manual page describes the user-level version of the FromMMapDevice
element.

Keyword arguments are:

=over 8

=item DEVNAME

String. The name of the interface where we send the packets.

=item BURST

Integer. Maximum number of packets to read per scheduling. Defaults to 32.

=item VERBOSE

Boolean. If true, displays log messages from the MMap library. Defaults to false.

=item DEBUG

Boolean. If true, displays debugging information from the MMap library. Defaults to false.

=back

=e

  FromMMapDevice(eth0) -> ...

=n

FromMMapDevice sets packets' extra length annotations as appropriate.

=h count read-only

Returns the number of packets read by the device.

=h avg_rx_bs read-only

Returns the average number of packets received at once (batch-style).

=h avg_proc_bs read-only

Returns the average number of packets pushed to the next element at once (batch-style).

=h reset_counts write-only

Resets "count" to zero.

=a ToMMapDevice.u */

class FromMMapDevice : public BatchElement {

	public:
		FromMMapDevice () CLICK_COLD;
		~FromMMapDevice() CLICK_COLD;

		const char *class_name() const	{ return "FromMMapDevice"; }
		const char *port_count() const	{ return "0/1-2"; }
		const char *processing() const	{ return PUSH; }
		int    configure_phase() const	{ return KernelFilter::CONFIGURE_PHASE_FROMDEVICE; }

		enum { default_snaplen = 2046 };

		int configure    (Vector<String> &, ErrorHandler *) 	CLICK_COLD;
		int initialize   (ErrorHandler *)			CLICK_COLD;
		void cleanup     (CleanupStage)				CLICK_COLD;
		void add_handlers()					CLICK_COLD;

		inline String ifname() const    { return _ifname; }
		inline int fd() const           { return _ring->sock_fd; }

		int setup_device(
			const String ifname, struct ring **ring, ErrorHandler *errh
		);
		void selected   (int fd, int mask);

		// ToMMapDevice needs the two methods below
		inline struct ring *get_fromdevice_mmap(const String ifname, ErrorHandler *errh) {
			if ( ifname != _ifname )
				return NULL;
			if ( !_ring )
				setup_device(ifname, &_ring, errh);
			return _ring;
		};
		inline int get_fromdevice_fd(const String ifname, bool *existed, ErrorHandler *errh) {
			if ( !_ring || _ring->sock_fd <= 0 ) {
				int fd = setup_device(_ifname, &_ring, errh);
				if ( fd <= 0 )
					return -1;
				*existed = false;
				return fd;
			}
			*existed = true;
			return _ring->sock_fd;
		};


	private:
		String       _ifname;
		struct ring *_ring;
		int          _burst_size;
		bool         _verbose;
		bool         _debug;

		counter_t    _n_recv;

		static String read_handler(Element *, void *) CLICK_COLD;
		static int write_handler  (const String &, Element *, void *, ErrorHandler *) CLICK_COLD;
};

CLICK_ENDDECLS
#endif
