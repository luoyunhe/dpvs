#ifndef __NAMESPACE_CONF_H__
#define __NAMESPACE_CONF_H__

#include "common.h"
#include "conf/common.h"
#include "conf/sockopts.h"

#define NAMESPACE_MAX_ID           255
#define NAMESPACE_ID_INVALID       NAMESPACE_MAX_ID
#define NAMESPACE_ID_ALL           NAMESPACE_MAX_ID
#define NAMESPACE_MAX_NAME_LEN     64

struct netns_conf {
    nsid_t nsid;
    char   name[NAMESPACE_MAX_NAME_LEN];
};

struct netns_conf_header {
    int    cnt;
    struct netns_conf ns_list[0];
};

#endif
