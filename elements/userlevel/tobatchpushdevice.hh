#ifndef CLICK_TOBATCHPUSHDEVICE_USERLEVEL_HH
#define CLICK_TOBATCHPUSHDEVICE_USERLEVEL_HH
#include <click/batchelement.hh>
#include <click/standard/storage.hh>
#include <click/string.hh>
#include "elements/userlevel/frombatchdevice.hh"
CLICK_DECLS

/*
 * =title ToBatchPushDevice.u
 * =c
 * ToBatchPushDevice(DEVNAME [, I<keywords>])
 * =s netdevices
 * sends packets to a Linux-based network device (user-level) in batch mode
 * =d
 *
 * This manual page describes the user-level version of the ToBatchPushDevice element.
 *
 * Sends packets out the named device using a full-push model with an internal queue.
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
 * Word. Defines the method ToBatchPushDevice will use to write packets to the
 * device. LINUX mode is currently supported.
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
 * Packets sent via ToBatchPushDevice should already have a link-level
 * header prepended. This means that ARP processing,
 * for example, must already have been done.
 *
 * The L<FromBatchDevice(n)> element's OUTBOUND keyword argument determines whether
 * FromBatchDevice receives packets sent by a ToBatchPushDevice element for the same
 * device.
 *
 * No putput ports.

 * KernelTun lets you send IP packets to the host kernel's IP processing code,
 * sort of like the kernel module's ToHost element.
 *
 * =a
 * FromBatchDevice.u */

class ToBatchPushDevice : public BatchElement, public Storage { public:

    ToBatchPushDevice()  CLICK_COLD;
    ~ToBatchPushDevice() CLICK_COLD;

    const char *class_name() const { return "ToBatchPushDevice"; }
    const char *port_count() const { return PORTS_1_0; }
    const char *processing() const { return PUSH; }

    int configure_phase() const	{
	return CONFIGURE_PHASE_PRIVILEGED;
    }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    int initialize(ErrorHandler *) CLICK_COLD;
    void cleanup(CleanupStage) CLICK_COLD;
    void add_handlers() CLICK_COLD;

    String ifname() const 	{ return _ifname; }
    int fd() const 		{ return _fd; }

    void push_packet(int port, Packet*);
#if HAVE_BATCH
    void push_batch(int port, PacketBatch *);
#endif

  protected:

    String _ifname;
    int _fd;

    enum { method_default, method_linux, method_pcap, method_devbpf, method_pcapfd };
    int _method;

    Packet *_q;

    int _burst;
    int _emitted;

    bool _debug;
    bool _my_fd;

    enum { h_debug, h_q, h_emitted };
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
