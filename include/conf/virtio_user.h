#ifndef __DPVS_VIRTIO_USER_CONF_H__
#define __DPVS_VIRTIO_USER_CONF_H__

#include "conf/common.h"

struct virtio_user_param {
    char    name[16];
    char    path[108];
    nsid_t  nsid;
    uint8_t mac[6];
};

#endif