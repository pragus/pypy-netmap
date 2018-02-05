#include "netmap_user.h"


struct netmap_ring* netmap_rxring(struct netmap_if* nifp, uint32_t index) {return NETMAP_RXRING(nifp, index);}
struct netmap_ring* netmap_txring(struct netmap_if* nifp, uint32_t index) {return NETMAP_TXRING(nifp, index);}