#ifndef CLICK_MMAPDEVICE_HH
#define CLICK_MMAPDEVICE_HH

#include <poll.h>
#include <netdb.h>
#include <assert.h>
#include <sys/mman.h>
#if !HAVE_DPDK
#include <net/ethernet.h>
#endif
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define COOKED_PACKET
#undef  P_8021Q

#define ETH_TYPE 0x88b5

////////////////////////////////////////////////////////////////////////////////////
// Supports datagrams (connectionless, unreliable messages of fixed maximum length).
////////////////////////////////////////////////////////////////////////////////////
#if !defined(COOKED_PACKET)

static const int SOCK_TYPE  = SOCK_DGRAM;
static const int SOCK_PROTO = ETH_P_802_3;
static const int BIND_PROTO = ETH_P_802_2;
static const int SEND_PROTO = ETH_TYPE;

#endif /* !defined(COOKED_PACKET) */
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
// Provides raw network protocol access via Ethernet without VLAN support.
////////////////////////////////////////////////////////////////////////////////////
#if defined(COOKED_PACKET) && !defined(P_8021Q)

static const int SOCK_TYPE  = SOCK_RAW;
static const int SOCK_PROTO = ETH_P_802_3;
static const int BIND_PROTO = ETH_P_802_2;
static const int SEND_PROTO = ETH_TYPE;

struct ether_header_s
{
  uint8_t  dhost[ETH_ALEN];
  uint8_t  shost[ETH_ALEN];
  uint16_t type;
} __attribute__ ((__packed__));

typedef struct ether_header_s ether_header_t;

#endif /* defined(COOKED_PACKET) && !defined(P_8021Q) */
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
// Provides raw network protocol access via Ethernet with VLAN support.
////////////////////////////////////////////////////////////////////////////////////
#if defined(COOKED_PACKET) && defined(P_8021Q)

static const int SOCK_TYPE  = SOCK_RAW;
static const int SOCK_PROTO = ETH_P_ALL;
static const int BIND_PROTO = ETH_P_ALL;
static const int SEND_PROTO = ETH_TYPE;

struct ether_header_s
{
  uint8_t   dhost[ETH_ALEN];
  uint8_t   shost[ETH_ALEN];
  uint16_t  tpid;
  uint16_t  tci;
  uint16_t  type;
} __attribute__ ((__packed__));

typedef struct ether_header_s ether_header_t;

#define E_8021Q_TPID 0x8100
#define E_8021Q_TCI  0xEFFE

#define E_8021Q_PCP 0x7     /* priority : highest -> better, from 0 to 7 */
#define E_8021Q_CFI 0
#define E_8021Q_VID 0xFFE   /* vlan id, from 0 (reserved) to 0xFFF (reserved) */

#endif /* defined(COOKED_PACKET) && defined(P_8021Q) */
////////////////////////////////////////////////////////////////////////////////////

#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/vector.hh>
#include <click/string.hh>

#define MEMORY_BARRIER()	asm volatile("" ::: "memory")

#ifndef __aligned_tpacket
# define __aligned_tpacket	__attribute__((aligned(TPACKET_ALIGNMENT)))
#endif

#ifndef __align_tpacket
# define __align_tpacket(x)	__attribute__((aligned(TPACKET_ALIGN(x))))
#endif

#define ALIGN_8(x)	(((x) + 8 - 1) & ~(8 - 1))

enum Mode {
	TX_MODE,
	RX_MODE
};

struct ring {
	struct iovec      *rd;
	void              *mmap_base;
	size_t             mmap_len;
	size_t             rd_len;
	struct sockaddr_ll link_layer;
	struct tpacket_req rx_req;
	struct tpacket_req tx_req;

	int flen;
	int sock_fd;
	int version;

	String ifname;

	struct pollfd tx_pfd;
	struct pollfd rx_pfd;

	unsigned   rd_num;

	void      *rx_rd_addr;
	unsigned   rx_rd_idx;
	unsigned   rx_rd_num;
	unsigned   rx_rd_size;
	unsigned   rx_rd_payload_offset;
	unsigned   rx_rd_payload_max_size;

	void      *tx_rd_addr;
	unsigned   tx_rd_idx;
	unsigned   tx_rd_num;
	unsigned   tx_rd_size;
	unsigned   tx_rd_payload_offset;
	unsigned   tx_rd_payload_max_size;
};

struct block_desc {
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 h1;
};

union frame_map {
	struct {
		struct tpacket_hdr tp_h __aligned_tpacket;
		struct sockaddr_ll s_ll __align_tpacket(sizeof(struct tpacket_hdr));
	} *v1;
	struct {
		struct tpacket2_hdr tp_h __aligned_tpacket;
		struct sockaddr_ll s_ll __align_tpacket(sizeof(struct tpacket2_hdr));
	} *v2;
	void *raw;
};

#if HAVE_INT64_TYPES
	typedef uint64_t counter_t;
#else
	typedef uint32_t counter_t;
#endif

CLICK_DECLS

class MMapDevice {
	public:
		static int NB_BLOCKS;
		static int BLOCK_SIZE;
		static int MTU_SIZE;
		static int BATCH_SIZE;

		static int  initialize    (ErrorHandler *errh);
		static int  static_cleanup();
		static void set_debug_info(bool &verbose, bool &debug);
		static int  add_rx_device (const String ifname, unsigned short burst_size);
		static int  add_tx_device (const String ifname, unsigned short burst_size);

		// MMap interface
		static struct ring * get_ring    (const String ifname);
		static struct ring * alloc_ring  (const String ifname);
		static int           open_socket (
			const String ifname, struct ring *ring, int ver
		);
		static int           setup_ring  (
			const String ifname, struct ring *ring,	int version
		);
		static int           mmap_ring   (
			const String ifname, struct ring *ring
		);
		static int           bind_ring   (
			const String ifname, struct ring *ring
		);
		static int           unmap_ring  (
			const String ifname
		);
		static int           close_socket(
			const String ifname, struct ring *ring
		);
		static int           setup_poll  (
			const String ifname, struct ring *ring, Mode mode
		);

		static int           walk_tx_ring_packet(
			const String ifname, struct ring *ring, Packet *p
		);
		static Packet       *walk_rx_ring_packet(
			const String ifname, struct ring *ring
		);

	#if HAVE_BATCH
		static int           walk_tx_ring_batch (
			const String ifname, struct ring *ring, PacketBatch *b
		);
		static PacketBatch  *walk_rx_ring_batch (
			const String ifname, struct ring *ring
		);
	#endif

		static int  tx_kernel_ready (void *base, int version);
		static void tx_user_ready   (void *base, int version);

		static int  rx_kernel_ready (void *base, int version);
		static void rx_user_ready   (void *base, int version);

		static void print_frame     (void *frame, size_t len);

		struct DevInfo {
			bool rx;
			bool tx;
			bool promisc;

			unsigned short burst_size;

			counter_t tx_send_calls;
			counter_t tx_total_bytes;
			counter_t rx_total_bytes;

			counter_t rx_recv_calls;
			counter_t tx_total_packets;
			counter_t rx_total_packets;

			inline DevInfo() :
				rx(false), tx(false), promisc(false),
				burst_size(32),
				tx_total_bytes(0), rx_total_bytes(0),
				tx_total_packets(0), rx_total_packets(0),
				tx_send_calls(0), rx_recv_calls(0) {};

			inline DevInfo(unsigned short burst) :
				rx(false), tx(false), promisc(false),
				burst_size(burst),
				tx_total_bytes(0), rx_total_bytes(0),
				tx_total_packets(0), rx_total_packets(0),
				tx_send_calls(0), rx_recv_calls(0) {};

			inline unsigned short get_burst_size() { return burst_size; };

			inline void update_tx_info(counter_t tx_pkts, counter_t tx_bytes, counter_t tx_calls=1) {
				assert( (tx_pkts >= 0) && (tx_bytes >= 0) && (tx_calls > 0) );
				tx_total_bytes   += tx_bytes;
				tx_total_packets += tx_pkts;
				tx_send_calls    += tx_calls;
			};

			inline void update_rx_info(counter_t rx_pkts, counter_t rx_bytes, counter_t rx_calls=1) {
				assert( (rx_pkts >= 0) && (rx_bytes >= 0) && (rx_calls > 0) );
				rx_total_bytes   += rx_bytes;
				rx_total_packets += rx_pkts;
				rx_recv_calls    += rx_calls;
			};
		};

	private:
		//////////////// Data structures to manage a set of devices ////////////////
		static bool                           _debug;
		static bool                           _verbose;
		static bool                           _is_initialized;
		static HashMap<String, DevInfo>       _devs;
		static HashMap<String, struct ring *> _ring_pool;
		////////////////////////////////////////////////////////////////////////////


		////////////////// Internal decomposition of ring methods //////////////////
		// TPACKET ver.1 and ver.2 are supported
		static int  _v1_tx_kernel_ready    (struct tpacket_hdr  *hdr);
		static void _v1_tx_user_ready      (struct tpacket_hdr  *hdr);
		static int  _v2_tx_kernel_ready    (struct tpacket2_hdr *hdr);
		static void _v2_tx_user_ready      (struct tpacket2_hdr *hdr);

		static int  _v1_rx_kernel_ready    (struct tpacket_hdr  *hdr);
		static void _v1_rx_user_ready      (struct tpacket_hdr  *hdr);
		static int  _v2_rx_kernel_ready    (struct tpacket2_hdr *hdr);
		static void _v2_rx_user_ready      (struct tpacket2_hdr *hdr);

		static void configure_ring         (struct ring *ring, unsigned int blocks);
		static int  set_packet_loss_discard(int sock_fd);
		////////////////////////////////////////////////////////////////////////////

		// Compatibility
		static int  test_user_bit_width  (void);
		static int  test_kernel_bit_width(void);

		// Device management
		static int  initialize_device(const String ifname, DevInfo &info) CLICK_COLD;
		static int  add_device       (
			const String ifname, Mode mode, unsigned short burst_size
		) CLICK_COLD;
		static bool has_device       (const String ifname);

		// Debugging
		static void debug_tpacket_frame(const void *base);
		static void debug_mmap_layout  (
			const struct tpacket_req *rx_packet_req,
			const struct tpacket_req *tx_packet_req
		);
};

static inline unsigned
next_power_of_two(unsigned n) {
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n++;
	return n;
}

CLICK_ENDDECLS

#endif
