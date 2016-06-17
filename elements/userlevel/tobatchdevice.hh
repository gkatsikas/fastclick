#ifndef CLICK_TOBATCHDEVICE_USERLEVEL_HH
#define CLICK_TOBATCHDEVICE_USERLEVEL_HH
#include <click/batchelement.hh>
#include <click/string.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include <click/notifier.hh>
#include "elements/userlevel/frombatchdevice.hh"
CLICK_DECLS

/*
 * =title ToBatchDevice.u
 * =c
 * ToBatchDevice(DEVNAME [, I<keywords>])
 * =s netdevices
 * sends packets to network device (user-level)
 * =d
 *
 * This manual page describes the user-level version of the ToBatchDevice element.
 *
 * Pulls packets in batch-style and sends them out.
 *
 * Keyword arguments are:
 *
 * =over 8
 *
 * =item BURST
 *
 * Integer. Maximum number of packets to pull per scheduling. Defaults to 1.
 *
 * =item METHOD
 *
 * Word. Defines the method ToBatchDevice will use to write packets to the
 * device. LINUX method is currently supported.
 *
 * =item DEBUG
 *
 * Boolean.  If true, print out debug messages.
 *
 * =back
 *
 * This element is only available at user level.
 *
 * =n
 *
 * Packets sent via ToBatchDevice should already have a link-level
 * header prepended. This means that ARP processing,
 * for example, must already have been done.
 *
 * The L<FromBatchDevice(n)> element's OUTBOUND keyword argument determines whether
 * FromBatchDevice receives packets sent by a ToBatchDevice element for the same
 * device.
 *
 * Packets that are written successfully are sent on output 0, if it exists.
 * Packets that fail to be written are pushed out output 1, if it exists.

 * KernelTun lets you send IP packets to the host kernel's IP processing code,
 * sort of like the kernel module's ToHost element.
 *
 * =a
 * FromBatchDevice.u, FromDump, ToDump, KernelTun, ToBatchDevice(n) */

class ToBatchDevice : public BatchElement { public:

    ToBatchDevice()  CLICK_COLD;
    ~ToBatchDevice() CLICK_COLD;

    const char *class_name() const		{ return "ToBatchDevice"; }
    const char *port_count() const		{ return "1/0-2"; }
    const char *processing() const		{ return "l/h"; }
    const char *flags() const			{ return "S2"; }

    int  configure_phase() const { return KernelFilter::CONFIGURE_PHASE_TODEVICE; }
    int  configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    int  initialize(ErrorHandler *) CLICK_COLD;
    void cleanup(CleanupStage) CLICK_COLD;
    void add_handlers() CLICK_COLD;

    String ifname() const	{ return _ifname; }
    int fd() const		{ return _fd; }

    bool run_task(Task *);
    void selected(int fd, int mask);

  protected:

    Task _task;
    Timer _timer;

    String _ifname;
    int _fd;
    enum { method_default, method_linux, method_pcap, method_devbpf, method_pcapfd };
    int _method;
    NotifierSignal _signal;

    Packet      *_q;
#if HAVE_BATCH
    PacketBatch *_q_batch;
#endif
    int _burst;

    bool _debug;
    bool _my_fd;
    int _backoff;
    int _pulls;

    enum { h_debug, h_signal, h_pulls, h_q };
    FromBatchDevice *find_fromdevice() const;
    int send_packet(Packet *p);
#if HAVE_BATCH
    int send_batch(PacketBatch *batch);
    int emit_batch(unsigned char *batch_data, unsigned short batch_len);
#endif

    static int write_param(const String &in_s, Element *e, void *vparam, ErrorHandler *errh) CLICK_COLD;
    static String read_param(Element *e, void *thunk) CLICK_COLD;
};

CLICK_ENDDECLS
#endif
