#include <assert.h>

#include "conf/common.h"
#include "namespace.h"
#include "netif.h"


static int nsid_map[NETIF_MAX_PORTS];

void nsid_init(void)
{
    for (int i = 0; i < NETIF_MAX_PORTS; i++){
        nsid_map[i] = -1;
    }
}

nsid_t nsid_get(portid_t id)
{
    nsid_t nsid = nsid_map[id];
    assert(nsid >= 0 && nsid<=DPVS_MAX_NETNS);
    return nsid ;
}

void nsid_set(portid_t port_id, nsid_t ns_id)
{
    nsid_map[port_id] = ns_id;
}