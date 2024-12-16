/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
/**
 * DPDK KNI device management.
 *
 * KNI device should be add/del by request. And any real devices,
 * can be attached on. Such as dpdk phy device, dpdk bonding
 * device and even virtual vlan device.
 *
 * raychen@qiyi.com, June 2017, initial.
 */
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "conf/common.h"
#include "dpdk.h"
#include "netif.h"
#include "conf/netif_addr.h"
#include "ctrl.h"
#include "kni.h"
#include "rte_ether.h"
#include "vlan.h"
#include "conf/kni.h"
#include "conf/sockopts.h"

#define Kni /* KNI is defined */
#define RTE_LOGTYPE_Kni     RTE_LOGTYPE_USER1

#define KNI_RX_RING_ELEMS       2048
bool g_kni_enabled = true;


/*
 * @dev     - real device kni attach to.
 * @kniname - optional, kni device name or auto generate.
 */
int kni_add_dev(struct netif_port *dev, const char *kniname)
{
    // todo
    return EDPVS_OK;
}

int kni_del_dev(struct netif_port *dev)
{
    // todo
    return EDPVS_OK;
}

/////////////// KNI FLOW //////////////

/*
 * Kni Address Flow:
 * The idea is to specify kni interface with an ip address, and isolate all traffic
 * target at the address to a dedicated nic rx-queue, which may avoid disturbances
 * of dataplane when overload.
 * Note that not all nic can support this flow type under the premise of sapool.
 * See `check_kni_addr_flow_support` for supported nics as we known so far. It's
 * encouraged to add more nic types satisfied the flow type.
 */

#define NETDEV_IXGBE_DRIVER_NAME      "ixgbe"
#define NETDEV_I40E_DRIVER_NAME       "i40e"
#define NETDEV_MLNX_DRIVER_NAME       "mlx5"

static bool check_kni_addr_flow_support(const struct netif_port *dev)
{
    return false;
}

static inline int kni_addr_flow_allowed(const struct netif_port *dev)
{
    return EDPVS_OK;
}

static struct kni_addr_flow* kni_addr_flow_lookup(const struct netif_port *dev,
                             const struct kni_addr_flow_entry *param) {
    return NULL;
}

static int kni_addr_flow_add(struct netif_port *dev, const struct kni_addr_flow_entry *param)
{
    return EDPVS_OK;
}

static int kni_addr_flow_del(struct netif_port *dev, const struct kni_addr_flow_entry *param)
{
    return EDPVS_OK;
}

static int kni_addr_flow_flush(struct netif_port *dev)
{
    return 0;
}

static void inline kni_addr_flow_fill_entry(const struct kni_addr_flow *flow,
        struct kni_conf_param *entry) {
}

static int kni_addr_flow_get(struct netif_port *dev, const struct kni_addr_flow_entry *param,
        struct kni_info **pentries, int *plen)
{
    return EDPVS_OK;
}

/////////////// KNI FLOW END //////////////

static int kni_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{

    return EDPVS_OK;
}

static int kni_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                        void **out, size_t *outsize)
{
    return EDPVS_OK;
}

static struct dpvs_sockopts kni_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_KNI_ADD,
    .set_opt_max    = SOCKOPT_SET_KNI_FLUSH,
    .set            = kni_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_KNI_LIST,
    .get_opt_max    = SOCKOPT_GET_KNI_LIST,
    .get            = kni_sockopt_get,
};

int kni_init(void)
{
    return EDPVS_OK;
}

int kni_ctrl_init(void)
{

    return EDPVS_OK;
}

int kni_ctrl_term(void)
{
    return EDPVS_OK;
}
