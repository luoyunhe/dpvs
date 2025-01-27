#ifndef __DPVS_NAMESPACE_H__
#define __DPVS_NAMESPACE_H__
#include <stdint.h>
#include "conf/common.h"
#include "conf/namespace.h"
#include "ctrl.h"



struct namespace {
    char                    name[NAMESPACE_MAX_NAME_LEN];    /* namespace name */
    nsid_t                  id;                              /* namespace id */
    struct list_head        list;                            /* list node hashed by id */
    struct list_head        nlist;                           /* list node hashed by name */
};

void nsid_init(void);
nsid_t nsid_get(portid_t id);
void nsid_set(portid_t port_id, nsid_t nsid);


struct namespace* namespace_get(nsid_t id);
struct namespace* namespace_get_by_name(const char *name);

int namespace_init(void);
int namespace_term(void);

#endif