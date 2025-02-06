#ifndef __DPVS_VIRTIO_USER_H__
#define __DPVS_VIRTIO_USER_H__
#include "conf/common.h"
#include "conf/virtio_user.h"
#include "ctrl.h"
#include "netif.h"


int virtio_user_init(void);
int virtio_user_term(void);
int remove_virtio_user(struct netif_port *port);

#endif