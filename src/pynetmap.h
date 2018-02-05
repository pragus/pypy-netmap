struct iovec {
        void *iov_base;
        size_t iov_len;
    };

typedef char ... u_char;
typedef int ... time_t;
typedef int ... suseconds_t;
typedef int ... u_int;

struct timeval {
   time_t      tv_sec;     /* seconds */
   suseconds_t tv_usec;    /* microseconds */
};

#define IFNAMSIZ ...
#define	NETMAP_API	...		/* current API version */

#define	NETMAP_MIN_API	...		/* min and max versions accepted */
#define	NETMAP_MAX_API	...
#define NM_CACHE_ALIGN	...



struct netmap_slot {
	uint32_t buf_idx;	/* buffer index */
	uint16_t len;		/* length for this slot */
	uint16_t flags;		/* buf changed, etc. */
	uint64_t ptr;		/* pointer for indirect buffers */
};

struct netmap_if {
 char ni_name[16]; /* name of the interface. */
 const uint32_t ni_version; /* API version, currently unused */
 const uint32_t ni_flags; /* properties */
 /*
	 * The number of packet rings available in netmap mode.
	 * Physical NICs can have different numbers of tx and rx rings.
	 * Physical NICs also have a 'host' ring pair.
	 * Additionally, clients can request additional ring pairs to
	 * be used for internal communication.
	 */
 const uint32_t ni_tx_rings; /* number of HW tx rings */
 const uint32_t ni_rx_rings; /* number of HW rx rings */
 uint32_t ni_bufs_head; /* head index for extra bufs */
 uint32_t ni_spare1[5];
 /*
	 * The following array contains the offset of each netmap ring
	 * from this structure, in the following order:
	 * NIC tx rings (ni_tx_rings); host tx ring (1); extra tx rings;
	 * NIC rx rings (ni_rx_rings); host tx ring (1); extra rx rings.
	 *
	 * The area is filled up by the kernel on NIOCREGIF,
	 * and then only read by userspace code.
	 */
 const ssize_t ring_ofs[0];
};

struct nmreq {
 char nr_name[16];
 uint32_t nr_version; /* API version */
 uint32_t nr_offset; /* nifp offset in the shared region */
 uint32_t nr_memsize; /* size of the shared region */
 uint32_t nr_tx_slots; /* slots in tx rings */
 uint32_t nr_rx_slots; /* slots in rx rings */
 uint16_t nr_tx_rings; /* number of tx rings */
 uint16_t nr_rx_rings; /* number of rx rings */
 uint16_t nr_ringid; /* ring(s) we care about */
 uint16_t nr_cmd;
 uint16_t nr_arg1; /* reserve extra rings in NIOCREGIF */
 uint16_t nr_arg2;
 uint32_t nr_arg3; /* req. extra buffers in NIOCREGIF */
 uint32_t nr_flags;
 /* various modes, extends nr_ringid */
 uint32_t spare2[1];
};

struct netmap_ring {
	/*
	 * buf_ofs is meant to be used through macros.
	 * It contains the offset of the buffer region from this
	 * descriptor.
	 */
	const int64_t	buf_ofs;
	const uint32_t	num_slots;	/* number of slots in the ring. */
	const uint32_t	nr_buf_size;
	const uint16_t	ringid;
	const uint16_t	dir;		/* 0: tx, 1: rx */

	uint32_t        head;		/* (u) first user slot */
	uint32_t        cur;		/* (u) wakeup point */
	uint32_t	tail;		/* (k) first kernel slot */

	uint32_t	flags;

	struct timeval	ts;		/* (k) time of last *sync() */

	struct netmap_slot slot[0];	/* array of slots. */
	...;
};

enum {
 NM_OPEN_NO_MMAP = 0x040000, /* reuse mmap from parent */
 NM_OPEN_IFNAME = 0x080000, /* nr_name, nr_ringid, nr_flags */
 NM_OPEN_ARG1 = 0x100000,
 NM_OPEN_ARG2 = 0x200000,
 NM_OPEN_ARG3 = 0x400000,
 NM_OPEN_RING_CFG = 0x800000, /* tx|rx rings|slots */
};

enum { NR_REG_DEFAULT = 0, /* backward compat, should not be used. */
 NR_REG_ALL_NIC = 1,
 NR_REG_SW = 2,
 NR_REG_NIC_SW = 3,
 NR_REG_ONE_NIC = 4,
 NR_REG_PIPE_MASTER = 5,
 NR_REG_PIPE_SLAVE = 6,
};

struct nm_ifreq {
 char nifr_name[16];
 char data[256];
};

struct nm_pkthdr { /* first part is the same as pcap_pkthdr */
 struct timeval ts;
 uint32_t caplen;
 uint32_t len;
 uint64_t flags; /* NM_MORE_PKTS etc */
 struct nm_desc *d;
 struct netmap_slot *slot;
 uint8_t *buf;
};
struct nm_stat { /* same as pcap_stat	*/
 u_int ps_recv;
 u_int ps_drop;
 u_int ps_ifdrop;
};
struct nm_desc {
 struct nm_desc *self; /* point to self if netmap. */
 int fd;
 void *mem;
 uint32_t memsize;
 int done_mmap; /* set if mem is the result of mmap */
 struct netmap_if * const nifp;
 uint16_t first_tx_ring, last_tx_ring, cur_tx_ring;
 uint16_t first_rx_ring, last_rx_ring, cur_rx_ring;
 struct nmreq req; /* also contains the nr_name = ifname */
 struct nm_pkthdr hdr;
 /*
	 * The memory contains netmap_if, rings and then buffers.
	 * Given a pointer (e.g. to nm_inject) we can compare with
	 * mem/buf_start/buf_end to tell if it is a buffer or
	 * some other descriptor in our region.
	 * We also store a pointer to some ring as it helps in the
	 * translation from buffer indexes to addresses.
	 */
 struct netmap_ring * const some_ring;
 void * const buf_start;
 void * const buf_end;
 /* parameters from pcap_open_live */
 int snaplen;
 int promisc;
 int to_ms;
 char *errbuf;
 /* save flags so we can restore them on close */
 uint32_t if_flags;
        uint32_t if_reqcap;
        uint32_t if_curcap;
 struct nm_stat st;
 char msg[512];
};


static struct nm_desc *nm_open(const char *ifname, const struct nmreq *req, uint64_t flags, const struct nm_desc *arg);
static int nm_close(struct nm_desc *);
static int nm_mmap(struct nm_desc *, const struct nm_desc *);
static int nm_parse(const char *ifname, struct nm_desc *d, char *err);
static int nm_inject(struct nm_desc *d, const void *buf, size_t size);
static u_char * nm_nextpkt(struct nm_desc *d, struct nm_pkthdr *hdr);
char* netmap_buf(struct netmap_ring* ring, uint32_t index);
struct netmap_ring* netmap_rxring(struct netmap_if* nifp, uint32_t index);
struct netmap_ring* netmap_txring(struct netmap_if* nifp, uint32_t index);