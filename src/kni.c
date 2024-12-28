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
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "conf/common.h"
#include "dpdk.h"
#include "namespace.h"
#include "netif.h"
#include "conf/netif_addr.h"
#include "ctrl.h"
#include "kni.h"
#include "rte_dev.h"
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
    char portargs[256];
    char ring_name[RTE_RING_NAMESIZE];
    struct rte_ring *rb;
    int ret;
    uint16_t port_id;
    struct rte_eth_conf port_conf;
    struct rte_eth_dev_info dev_info;
    char ifname[IFNAMSIZ];
    char virtio_user_ifname[sizeof("virtio_user_")+IFNAMSIZ];


    if (kniname && strlen(kniname))
        snprintf(ifname, sizeof(ifname), "%s", kniname);
    else
        snprintf(ifname, sizeof(ifname), "%s", dev->name);

    snprintf(virtio_user_ifname, sizeof(virtio_user_ifname), "virtio_user_%s", ifname);

    if (!g_kni_enabled)
        return EDPVS_OK;

    if (!dev)
        return EDPVS_INVAL;

    if (dev->type == PORT_TYPE_BOND_SLAVE)
        return EDPVS_NOTSUPP;

    if (kni_dev_exist(dev)) {
        RTE_LOG(ERR, Kni, "%s: dev %s has already attached with kni\n",
                __func__, dev->name);
        return EDPVS_EXIST;
    }

    // 创建虚拟设备参数，指定路径，设备名称，mac地址等
    snprintf(portargs, sizeof(portargs),
        "path=/dev/vhost-net,queues=1,queue_size=1024,iface=%s,mac=" RTE_ETHER_ADDR_PRT_FMT,
        ifname, RTE_ETHER_ADDR_BYTES(&dev->addr));
        
    // 把设备加入到系统
    ret = rte_eal_hotplug_add("vdev", virtio_user_ifname, portargs);
    if (ret != 0) {
        RTE_LOG(ERR, Kni, "%s: Failed to add kni device for %s\n",
                __func__, dev->name);
        return EDPVS_DPDKAPIFAIL;
    }
    if (rte_eth_dev_get_port_by_name(virtio_user_ifname, &port_id) != 0)
    {
        RTE_LOG(ERR, Kni, "%s: Failed to get port by name\n",
                __func__);
        ret = EDPVS_DPDKAPIFAIL;
        goto clean;
    }
    nsid_set(port_id, dev->nsid);
    memset(&port_conf, 0, sizeof(struct rte_eth_conf));
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0)
    {
        RTE_LOG(ERR, Kni, "%s: Failed to get dev info\n",
                __func__);
        ret = EDPVS_DPDKAPIFAIL;
        goto clean;
    }
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret != 0) {
        RTE_LOG(ERR, Kni, "%s: Failed to configure eth dev, code %d\n",
                __func__, ret);
        ret = EDPVS_DPDKAPIFAIL;
        goto clean;
    }
    ret = rte_eth_rx_queue_setup(port_id, 0,  1024, dev->socket, NULL, pktmbuf_pool[dev->socket]);
    if (ret != 0) {
        RTE_LOG(ERR, Kni, "%s: Failed to setup rx queue, code %d\n",
                __func__, ret);
        ret = EDPVS_DPDKAPIFAIL;
        goto clean;
    }
    ret = rte_eth_tx_queue_setup(port_id, 0, 1024, dev->socket, NULL);
    if (ret != 0) {
        RTE_LOG(ERR, Kni, "%s: Failed to setup tx queue, code %d\n",
                __func__, ret);
        ret = EDPVS_DPDKAPIFAIL;
        goto clean;
    }
    ret = rte_eth_dev_start(port_id);
    if (ret != 0) {
        RTE_LOG(ERR, Kni, "%s: Failed to start eth dev, code %d\n",
                __func__, ret);
        ret = EDPVS_DPDKAPIFAIL;
        goto clean;
    }

    snprintf(ring_name, sizeof(ring_name), "kni_rx_ring_%s",
            ifname);
    rb = rte_ring_create(ring_name, KNI_RX_RING_ELEMS,
                        dev->socket, RING_F_SC_DEQ);
    if (unlikely(!rb)) {
        RTE_LOG(ERR, Kni, "[%s] Failed to create kni rx ring.\n", __func__);
        ret = EDPVS_DPDKAPIFAIL;
        goto clean;
    }


    snprintf(dev->kni.name, sizeof(dev->kni.name), "%s", ifname);
    dev->kni.addr = dev->addr;
    dev->kni.port_id = port_id;
    dev->kni.rx_ring = rb;

    return EDPVS_OK;
clean:
    rte_eal_hotplug_remove("vdev", ifname);
    return ret;
}

int kni_del_dev(struct netif_port *dev)
{
    char virtio_user_ifname[sizeof("virtio_user_")+IFNAMSIZ];
    int ret;

    snprintf(virtio_user_ifname, sizeof(virtio_user_ifname), "virtio_user_%s", dev->kni.name);

    if (!g_kni_enabled)
        return EDPVS_OK;
    ret = rte_eal_hotplug_remove("vdev", virtio_user_ifname);
    if (ret !=0) {
        RTE_LOG(ERR, Kni, "[%s] Failed to remove vdev\n", __func__);
    }
    if (!kni_dev_exist(dev))
        return EDPVS_INVAL;
    rte_ring_free(dev->kni.rx_ring);
    dev->kni.port_id = 0;
    dev->kni.rx_ring = NULL;
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
