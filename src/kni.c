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
#include "netif.h"
#include "conf/netif_addr.h"
#include "ctrl.h"
#include "kni.h"
#include "rte_dev.h"
#include "rte_ether.h"
#include "conf/kni.h"
#include "conf/sockopts.h"

#define Kni /* KNI is defined */

#define KNI_RX_RING_ELEMS       2048
bool g_kni_enabled = true;


#ifdef CONFIG_KNI_VIRTIO_USER

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// TODO: let the params configurable
static uint16_t virtio_queues = 1;
static int virtio_queue_size = 1024;
static char vhost_dev_path[PATH_MAX] = "/dev/vhost-net";

static inline const char *kni_get_name(const struct netif_kni *kni)
{
    return kni->kni->ifname;
}

static struct virtio_kni* virtio_kni_alloc(struct netif_port *dev, const char *ifname)
{
    int err;
    portid_t pid;
    struct virtio_kni *kni = NULL;
    char portargs[1024];
    char portname[RTE_ETH_NAME_MAX_LEN];

    kni = rte_zmalloc("virtio_kni", sizeof(*kni), RTE_CACHE_LINE_SIZE);
    if (unlikely(!kni))
        return NULL;

    kni->master = dev;
    kni->queues = virtio_queues;
    kni->queue_size = virtio_queue_size;
    kni->path = rte_malloc("virtio_kni", strlen(vhost_dev_path) + 1, RTE_CACHE_LINE_SIZE);
    if (unlikely(!kni->path))
        goto errout;
    strcpy(kni->path, vhost_dev_path);
    err = snprintf(kni->dpdk_portname, sizeof(kni->dpdk_portname), "virtio_user%u", dev->id);
    if (unlikely(err > sizeof(kni->dpdk_portname))) {
        RTE_LOG(ERR, Kni, "%s: no enough room for dpdk_portname, expect %d\n", __func__, err);
        goto errout;
    }
    if (ifname)
        strncpy(kni->ifname, ifname, sizeof(kni->ifname) - 1);
    else
        snprintf(kni->ifname, sizeof(kni->ifname), "%s.kni", dev->name);

    // Refer to drivers/net/virtio/virtio_user_ethdev.c:virtio_user_driver for all supported args.
    // FIXME: Arg `speed` has no effects so that the virtio_kni port speed is always 10Mbps.
    err = snprintf(portargs, sizeof(portargs), "path=%s,queues=%u,queue_size=%u,iface=%s,"
            "speed=10000,mac=" RTE_ETHER_ADDR_PRT_FMT, kni->path, kni->queues, kni->queue_size,
            kni->ifname, RTE_ETHER_ADDR_BYTES(&dev->addr));
    if (unlikely(err > sizeof(portargs))) {
        RTE_LOG(ERR, Kni, "%s: no enough room for portargs, expect %d\n", __func__, err);
        goto errout;
    }

    err = rte_eal_hotplug_add("vdev", kni->dpdk_portname, portargs);
    if (err < 0) {
        RTE_LOG(ERR, Kni, "%s: virtio_kni hotplug_add failed: %d\n", __func__, err);
        goto errout;
    }

    RTE_ETH_FOREACH_DEV(pid) {
        rte_eth_dev_get_name_by_port(pid, portname);
        if (!strncmp(portname, kni->dpdk_portname, sizeof(kni->dpdk_portname))) {
            kni->dpdk_pid = pid;
            RTE_LOG(INFO, Kni, "%s: virtio_kni allocation succeed: ifname=%s, dpdk port %s, "
                    "id %d\n", __func__, kni->ifname, kni->dpdk_portname, pid);
            return kni;
        }
    }
    RTE_LOG(ERR, Kni, "%s: virtio_kni port id not found: ifname=%s, dpdk portname=%s\n",
            __func__, kni->ifname, kni->dpdk_portname);

errout:
    if (kni->path)
        rte_free(kni->path);
    if (kni)
        rte_free(kni);
    return NULL;
}

static void virtio_kni_free(struct virtio_kni **pkni)
{
    int err;
    struct virtio_kni *kni = *pkni;

    err = rte_eal_hotplug_remove("vdev", kni->dpdk_portname);
    if (err < 0)
        RTE_LOG(WARNING, Kni, "%s: virtio_kni hotplug_remove failed: %d\n", __func__, err);

    rte_free(kni->path);
    rte_free(kni);

    *pkni = NULL;
}

static struct rte_eth_conf virtio_kni_eth_conf = {
    .rxmode = {
        .mq_mode        = RTE_ETH_MQ_RX_NONE,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode    = RTE_ETH_MQ_TX_NONE,
        .offloads   = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
                        | RTE_ETH_TX_OFFLOAD_TCP_TSO | RTE_ETH_TX_OFFLOAD_UDP_TSO
                        | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM
                        | RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_SCTP_CKSUM,
    },
};

static int virtio_kni_start(struct virtio_kni *kni)
{
    uint16_t q;
    int err;
    struct rte_eth_dev_info dev_info;
    struct rte_ether_addr macaddr;
    char strmac1[32], strmac2[32];

    rte_memcpy(&kni->eth_conf, &virtio_kni_eth_conf, sizeof(kni->eth_conf));

    err = rte_eth_dev_info_get(kni->dpdk_pid, &dev_info);
    if (err == EDPVS_OK) {
        kni->eth_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
        kni->eth_conf.rxmode.offloads &= dev_info.rx_offload_capa;
        kni->eth_conf.txmode.offloads &= dev_info.tx_offload_capa;
    } else {
        RTE_LOG(WARNING, Kni, "%s: rte_eth_dev_info_get(%s) failed: %d\n", __func__,
                kni->ifname, err);
    }

    err = rte_eth_dev_configure(kni->dpdk_pid, kni->queues, kni->queues, &kni->eth_conf);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: failed to config %s: %d\n", __func__, kni->ifname, err);
        return EDPVS_DPDKAPIFAIL;
    }

    for (q = 0; q < kni->queues; q++) {
        err = rte_eth_rx_queue_setup(kni->dpdk_pid, q, kni->queue_size,
                kni->master->socket, NULL, pktmbuf_pool[kni->master->socket]);
        if (err != EDPVS_OK) {
            RTE_LOG(ERR, Kni, "%s: failed to configure %s's queue %u: %d\n", __func__,
                    kni->ifname, q, err);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    for (q = 0; q < kni->queues; q++) {
        err = rte_eth_tx_queue_setup(kni->dpdk_pid, q, kni->queue_size, kni->master->socket, NULL);
        if (err != EDPVS_OK) {
            RTE_LOG(ERR, Kni, "%s: failed to configure %s's queue %u: %d\n", __func__,
                    kni->ifname, q, err);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    err = rte_eth_dev_start(kni->dpdk_pid);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: failed to start %s: %d\n", __func__, kni->ifname, err);
        return EDPVS_DPDKAPIFAIL;
    }

    //disable_kni_tx_csum_offload(kni->ifname);

    rte_eth_macaddr_get(kni->dpdk_pid, &macaddr);
    if (!eth_addr_equal(&macaddr, &kni->master->kni.addr)) {
        RTE_LOG(INFO, Kni, "%s: update %s mac addr: %s->%s\n", __func__, kni->ifname,
                eth_addr_dump(&kni->master->kni.addr, strmac1, sizeof(strmac1)),
                eth_addr_dump(&macaddr, strmac2, sizeof(strmac2)));
        kni->master->kni.addr = macaddr;
    }

    RTE_LOG(INFO, Kni, "%s: %s started success\n", __func__, kni->ifname);
    return EDPVS_OK;
}

static int virtio_kni_stop(struct virtio_kni *kni)
{
    int err;

    err = rte_eth_dev_stop(kni->dpdk_pid);
    if (err != EDPVS_OK) {
        if (err == EBUSY) {
            RTE_LOG(WARNING, Kni, "%s: %s is busy, retry later ...\n", __func__, kni->ifname);
            return EDPVS_BUSY;
        }
        RTE_LOG(ERR, Kni, "%s: failed to stop %s: %d\n", __func__, kni->ifname, err);
    }

    err = rte_eth_dev_close(kni->dpdk_pid);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: failed to close %s: %d\n", __func__, kni->ifname, err);
        return EDPVS_DPDKAPIFAIL;
    }

    RTE_LOG(INFO, Kni, "%s: %s stopped success\n", __func__, kni->ifname);
    return EDPVS_OK;
}

#else // !CONFIG_KNI_VIRTIO_USER
static inline const char *kni_get_name(const struct netif_kni *kni)
{
    return rte_kni_get_name(kni->kni);
}

static void kni_fill_conf(const struct netif_port *dev, const char *ifname,
                          struct rte_kni_conf *conf)
{
    struct rte_eth_dev_info info = {0};

    memset(conf, 0, sizeof(*conf));
    conf->group_id = dev->id;
    conf->mbuf_size = rte_pktmbuf_data_room_size(pktmbuf_pool[dev->socket]) - RTE_PKTMBUF_HEADROOM;

    /*
     * kni device should use same mac as real device,
     * because it may config same IP of real device.
     * diff mac means kni cannot accept packets sent
     * to real-device.
     */
    memcpy(conf->mac_addr, dev->addr.addr_bytes, sizeof(conf->mac_addr));

    if (dev->type == PORT_TYPE_GENERAL) { /* dpdk phy device */
        rte_eth_dev_info_get(dev->id, &info);
#if RTE_VERSION < RTE_VERSION_NUM(18, 11, 0, 0)
        conf->addr = info.pci_dev->addr;
        conf->id = info.pci_dev->id;
#else
        if (info.device) {
            const struct rte_bus *bus = NULL;
            const struct rte_pci_device *pci_dev;
            bus = rte_bus_find_by_device(info.device);
            if (bus && !strcmp(bus->name, "pci")) {
                pci_dev = RTE_DEV_TO_PCI(info.device);
                conf->addr = pci_dev->addr;
                conf->id = pci_dev->id;
            }
        }
#endif
    }

    if (ifname && strlen(ifname))
        snprintf(conf->name, sizeof(conf->name), "%s", ifname);
    else
        snprintf(conf->name, sizeof(conf->name), "%s.kni", dev->name);

    return;
}
#endif // CONFIG_KNI_VIRTIO_USER

/*
 * @dev     - real device kni attach to.
 * @kniname - optional, kni device name or auto generate.
 */
int kni_add_dev(struct netif_port *dev, const char *kniname)
{
    int err;
    struct rte_ring *rb;
#ifdef CONFIG_KNI_VIRTIO_USER
    struct virtio_kni *kni;
#endif
    char ring_name[RTE_RING_NAMESIZE];

    if (!g_kni_enabled)
        return EDPVS_OK;

    if (!dev)
        return EDPVS_INVAL;

    if (kni_dev_exist(dev)) {
        RTE_LOG(ERR, Kni, "%s: dev %s has already attached with kni\n",
                __func__, dev->name);
        return EDPVS_EXIST;
    }

#ifdef CONFIG_KNI_VIRTIO_USER
    kni = virtio_kni_alloc(dev, kniname);
    if (!kni)
        return EDPVS_RESOURCE;
#endif

#ifdef CONFIG_KNI_VIRTIO_USER
    snprintf(ring_name, sizeof(ring_name), "kni_rx_ring_%s", kni->ifname);
#endif
    rb = rte_ring_create(ring_name, KNI_RX_RING_ELEMS,
                         rte_socket_id(), RING_F_SC_DEQ);
    if (unlikely(!rb)) {
        RTE_LOG(ERR, Kni, "%s: failed to create kni rx ring\n", __func__);
#ifdef CONFIG_KNI_VIRTIO_USER
        virtio_kni_free(&kni);
#endif
        return EDPVS_DPDKAPIFAIL;
    }

#ifdef CONFIG_KNI_VIRTIO_USER
    if ((err = virtio_kni_start(kni)) != EDPVS_OK) {
        rte_ring_free(rb);
        virtio_kni_free(&kni);
        return err;
    }
#endif

    dev->kni.addr = dev->addr;
    dev->kni.rx_ring = rb;
    dev->kni.kni = kni;
    snprintf(dev->kni.name, sizeof(dev->kni.name), "%s", kni_get_name(&dev->kni));

    dev->kni.flags |= NETIF_PORT_FLAG_RUNNING;
    return EDPVS_OK;
}

int kni_del_dev(struct netif_port *dev)
{
    int err;

    if (!g_kni_enabled)
        return EDPVS_OK;

    if (!kni_dev_exist(dev))
        return EDPVS_INVAL;

    dev->kni.flags &= ~((uint16_t)NETIF_PORT_FLAG_RUNNING);

#ifdef CONFIG_KNI_VIRTIO_USER
    err = virtio_kni_stop(dev->kni.kni);
    if (err != EDPVS_OK) {
        // FIXME: retry when err is EDPVS_BUSY
        RTE_LOG(ERR, Kni, "%s: failed to stop virtio kni %s: %d\n", __func__, dev->kni.name, err);
        return err;
    }
    virtio_kni_free(&dev->kni.kni);
#else
    err = rte_kni_release(dev->kni.kni);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: failed to release kni %s: %d\n", __func__, dev->kni.name, err);
        return err;
    }
#endif

    rte_ring_free(dev->kni.rx_ring);
    dev->kni.kni = NULL;
    dev->kni.rx_ring = NULL;
    return EDPVS_OK;
}

static int kni_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    return EDPVS_NOTSUPP;
}

static int kni_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                        void **out, size_t *outsize)
{
    return EDPVS_NOTSUPP;
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

int kni_ctrl_init(void)
{
    int err;

    if (!g_kni_enabled)
        return EDPVS_OK;

    err = sockopt_register(&kni_sockopts);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: fail to register kni_sockopts -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    return EDPVS_OK;
}

int kni_ctrl_term(void)
{
    int err;

    if (!g_kni_enabled)
        return EDPVS_OK;

    err = sockopt_unregister(&kni_sockopts);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, Kni, "%s: fail to unregister kni_sockopts -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    return EDPVS_OK;
}
