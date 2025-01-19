#ifndef __DPVS_NAMESPACE_H__
#define __DPVS_NAMESPACE_H__
#include <stdint.h>
#include "conf/common.h"


void nsid_init(void);
nsid_t nsid_get(portid_t id);
void nsid_set(portid_t port_id, nsid_t nsid);

#endif