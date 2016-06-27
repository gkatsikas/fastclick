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

/*
 * The data structure that helps to manage the ring buffers
 */
struct ring {
	// An array of I/O vectors (ring descriptors)
	struct iovec      *rd;
	// A pointer to the starting point of the shared memory
	void              *mmap_base;
	// The size of the shared memory
	size_t             mmap_len;
	// The number of ring descriptors
	unsigned           rd_num;
	// The length of the ring descriptors's area
	size_t             rd_len;
	// Some link layer information about the socket
	struct sockaddr_ll link_layer;
	// Tx/Rx TPACKET information
	// (http://lxr.free-electrons.com/source/include/uapi/linux/if_packet.h#L267)
	struct tpacket_req rx_req;
	struct tpacket_req tx_req;

	// Maximum frame length suppported
	int flen;
	// The socket descriptor associated with the memory
	int sock_fd;
	// The TPACKET version we use (We support TPACKET_V1, TPACKET_V2)
	int version;

	// The name of the interface
	String ifname;

	// Tx/Rx polling data structures
	struct pollfd tx_pfd;
	struct pollfd rx_pfd;

	// The starting point of the Rx rings in the memory
	void      *rx_rd_addr;
	// The current index in this memory
	unsigned   rx_rd_idx;
	// The number of Rx ring descriptors
	unsigned   rx_rd_num;
	// The size of the Rx memory zone
	unsigned   rx_rd_size;

	// The starting point of the Tx rings in the memory
	void      *tx_rd_addr;
	// The current index in this memory
	unsigned   tx_rd_idx;
	// The number of Tx ring descriptors
	unsigned   tx_rd_num;
	// The size of the tx memory zone
	unsigned   tx_rd_size;
};

struct block_desc {
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 h1;
};

// Frame representation using the TPACKET format
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
		// The number of memory blocks
		static int NB_BLOCKS;
		// The size of each block in bytes
		// A greater power of two of the page size
		static int BLOCK_SIZE;
		// The MTU will help us define the maximum frame size
		static int MTU_SIZE;

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

		/*
		 * Device representation with statistics
		 */
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
		static bool _debug;
		static bool _verbose;
		static bool _is_initialized;

		//////////////// Data structures to manage a set of devices ////////////////
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
