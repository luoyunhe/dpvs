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
#include "netif.h"
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include "conf/namespace.h"
#include "dpdk.h"
#include "conf/common.h"
#include "generic/rte_cycles.h"
#include "generic/rte_rwlock.h"
#include "global_data.h"
#include "inetaddr.h"
#include "namespace.h"
#include "netif.h"
#include "netif_addr.h"
#include "conf/netif_addr.h"
#include "rte_ethdev.h"
#include "ctrl.h"
#include "list.h"
#include "kni.h"
#include <rte_version.h>
#include "conf/netif.h"
#include "rte_lcore.h"
#include "rte_malloc.h"
#include "tc/tc.h"
#include "timer.h"
#include "parser/parser.h"
#include "neigh.h"
#include "scheduler.h"
#include "linux_if.h"
#include "virtio_user.h"

#include <rte_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ipvs/redirect.h>
#include <rte_avp_common.h>
#include <rte_bus.h>
#include <unistd.h>

#ifdef CONFIG_ICMP_REDIRECT_CORE
#include "icmp.h"
#endif

#define NETIF_PKTPOOL_NB_MBUF_DEF   65535
#define NETIF_PKTPOOL_NB_MBUF_MIN   1023
#define NETIF_PKTPOOL_NB_MBUF_MAX   134217727
int netif_pktpool_nb_mbuf = NETIF_PKTPOOL_NB_MBUF_DEF;

#define NETIF_PKTPOOL_MBUF_CACHE_DEF    256
#define NETIF_PKTPOOL_MBUF_CACHE_MIN    32
#define NETIF_PKTPOOL_MBUF_CACHE_MAX    8192
int netif_pktpool_mbuf_cache = NETIF_PKTPOOL_MBUF_CACHE_DEF;

#define NETIF_NB_RX_DESC_DEF    256
#define NETIF_NB_RX_DESC_MIN    16
#define NETIF_NB_RX_DESC_MAX    8192

#define NETIF_NB_TX_DESC_DEF    512
#define NETIF_NB_TX_DESC_MIN    16
#define NETIF_NB_TX_DESC_MAX    8192

#define NETIF_PKT_PREFETCH_OFFSET   3
#define NETIF_ISOL_RXQ_RING_SZ_DEF  1048576 // 1M bytes

#define ARP_RING_SIZE 2048

#define RETA_CONF_SIZE  (RTE_ETH_RSS_RETA_SIZE_512 / RTE_ETH_RETA_GROUP_SIZE)

/* physical nic id = phy_pid_base + index */
static portid_t phy_pid_base = 0;
static portid_t phy_pid_end = -1; // not inclusive
/* bond device id = bond_pid_base + index */

static portid_t port_id_end = 0;

static uint16_t g_nports;

/*for arp process*/
static struct rte_ring *arp_ring[DPVS_MAX_NETNS][DPVS_MAX_LCORE] = {0};

#define NETIF_BOND_MODE_DEF         BONDING_MODE_ROUND_ROBIN
#define NETIF_BOND_NUMA_NODE_DEF    0

struct port_conf_stream {
    int port_id;
    char name[32];
    char kni_name[32];

    int rx_queue_nb;
    int rx_desc_nb;
    char rss[32];
    int mtu;

    int tx_queue_nb;
    int tx_desc_nb;
    bool tx_mbuf_fast_free;

    bool promisc_mode;
    bool allmulticast;

    struct list_head port_list_node;
};

struct bond_options {
    bool dedicated_queues_enable;
};

struct bond_conf_stream {
    int port_id;
    char name[32];
    char kni_name[32];
    int mode;
    int numa_node;
    char primary[32];
    char slaves[NETIF_MAX_BOND_SLAVES][32];
    struct bond_options options;
    struct list_head bond_list_node;
};

struct queue_conf_stream {
    char port_name[32];
    int rx_queues[NETIF_MAX_QUEUES];
    int tx_queues[NETIF_MAX_QUEUES];
    int isol_rxq_lcore_ids[NETIF_MAX_QUEUES];
    int isol_rxq_ring_sz;
    struct list_head queue_list_node;
};

struct worker_conf_stream {
    int cpu_id;
    char name[32];
    char type[32];
    struct list_head port_list;
    struct list_head worker_list_node;
};

// static struct list_head port_list;      /* device configurations from cfgfile */
static struct list_head worker_list;    /* lcore configurations from cfgfile */

#define NETIF_PORT_TABLE_BITS 8
#define NETIF_PORT_TABLE_BUCKETS (1 << NETIF_PORT_TABLE_BITS)
#define NETIF_PORT_TABLE_MASK (NETIF_PORT_TABLE_BUCKETS - 1)
static struct list_head port_tab[NETIF_PORT_TABLE_BUCKETS]; /* hashed by id */
static struct list_head port_ntab[NETIF_PORT_TABLE_BUCKETS]; /* hashed by name */
static rte_rwlock_t port_rwlock[NETIF_PORT_TABLE_BUCKETS];
static rte_rwlock_t port_nrwlock[NETIF_PORT_TABLE_BUCKETS];

#define NETIF_CTRL_BUFFER_LEN     4096

/* function declarations */
static void kni_lcore_loop(void *dummy);

bool is_physical_port(portid_t pid)
{
    return pid >= phy_pid_base && pid < phy_pid_end;
}


void netif_physical_port_range(portid_t *start, portid_t *end)
{
    if (start)
        *start = phy_pid_base;
    if (end)
        *end = phy_pid_end;
}

bool is_lcore_id_valid(lcoreid_t cid)
{
    if (unlikely(cid >= DPVS_MAX_LCORE))
        return false;

    return ((cid == rte_get_main_lcore()) ||
            (cid == g_kni_lcore_id) ||
            (g_slave_lcore_mask & (1L << cid)) ||
            (g_isol_rx_lcore_mask & (1L << cid)));
}

static bool is_lcore_id_fwd(lcoreid_t cid)
{
    if (unlikely(cid >= DPVS_MAX_LCORE))
        return false;

    return ((cid == rte_get_main_lcore()) ||
            (g_slave_lcore_mask & (1L << cid)));
}

static void netif_defs_handler(vector_t tokens)
{
}

static void pktpool_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pktpool_size;

    assert(str);
    pktpool_size = atoi(str);
    if (pktpool_size < NETIF_PKTPOOL_NB_MBUF_MIN ||
            pktpool_size > NETIF_PKTPOOL_NB_MBUF_MAX) {
        RTE_LOG(WARNING, NETIF, "invalid pktpool_size %s, using default %d\n",
                str, NETIF_PKTPOOL_NB_MBUF_DEF);
        netif_pktpool_nb_mbuf = NETIF_PKTPOOL_NB_MBUF_DEF;
    } else {
        is_power2(pktpool_size, 1, &pktpool_size);
        RTE_LOG(INFO, NETIF, "pktpool_size = %d (round to 2^n-1)\n", pktpool_size - 1);
        netif_pktpool_nb_mbuf = pktpool_size - 1;
    }

    FREE_PTR(str);
}

static void pktpool_cache_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int cache_size;

    assert(str);
    cache_size = atoi(str);
    if (cache_size < NETIF_PKTPOOL_MBUF_CACHE_MIN ||
            cache_size > NETIF_PKTPOOL_MBUF_CACHE_MAX) {
        RTE_LOG(WARNING, NETIF, "invalid pktpool_cache_size %s, using default %d\n",
                str, NETIF_PKTPOOL_MBUF_CACHE_DEF);
        netif_pktpool_mbuf_cache = NETIF_PKTPOOL_MBUF_CACHE_DEF;
    } else {
        is_power2(cache_size, 0, &cache_size);
        RTE_LOG(INFO, NETIF, "pktpool_cache_size = %d (round to 2^n)\n", cache_size);
        netif_pktpool_mbuf_cache = cache_size;
    }

    FREE_PTR(str);
}

static void worker_defs_handler(vector_t tokens)
{
    struct worker_conf_stream *worker_cfg, *worker_cfg_next;
    struct queue_conf_stream *queue_cfg, *queue_cfg_next;

    list_for_each_entry_safe(worker_cfg, worker_cfg_next, &worker_list,
            worker_list_node) {
        list_del(&worker_cfg->worker_list_node);
        list_for_each_entry_safe(queue_cfg, queue_cfg_next, &worker_cfg->port_list,
                queue_list_node) {
            list_del(&queue_cfg->queue_list_node);
            rte_free(queue_cfg);
        }
        rte_free(worker_cfg);
    }
}

static void worker_handler(vector_t tokens)
{
    assert(VECTOR_SIZE(tokens) >= 1);

    char *str;
    struct worker_conf_stream *worker_cfg = rte_malloc(NULL,
            sizeof(struct worker_conf_stream), RTE_CACHE_LINE_SIZE);
    if (!worker_cfg) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return;
    }

    INIT_LIST_HEAD(&worker_cfg->port_list);

    str = VECTOR_SLOT(tokens, 1);
    RTE_LOG(INFO, NETIF, "netif worker config: %s\n", str);
    strncpy(worker_cfg->name, str, sizeof(worker_cfg->name));

    list_add(&worker_cfg->worker_list_node, &worker_list);
}

static void worker_type_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);

    assert(str);
    if (!strcmp(str, "master") || !strcmp(str, "slave")
        || !strcmp(str, "kni")) {
        RTE_LOG(INFO, NETIF, "%s:type = %s\n", current_worker->name, str);
        strncpy(current_worker->type, str, sizeof(current_worker->type));
    } else {
        RTE_LOG(WARNING, NETIF, "invalid %s:type %s, using default %s\n",
                current_worker->name, str, "slave");
        strncpy(current_worker->type, "slave", sizeof(current_worker->type));
    }

    FREE_PTR(str);
}

static void cpu_id_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int cpu_id;
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);

    assert(str);
    if (strspn(str, "0123456789") != strlen(str)) {
        RTE_LOG(WARNING, NETIF, "invalid %s:cpu_id %s, using default 0\n",
                current_worker->name, str);
        current_worker->cpu_id = 0;
    } else {
        cpu_id = atoi(str);
        RTE_LOG(INFO, NETIF, "%s:cpu_id = %d\n", current_worker->name, cpu_id);
        current_worker->cpu_id = cpu_id;

        if (!strcmp(current_worker->type, "kni"))
            g_kni_lcore_id = cpu_id;
    }

    FREE_PTR(str);
}

#ifdef CONFIG_ICMP_REDIRECT_CORE
static void cpu_icmp_redirect_handler(vector_t tokens)
{
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);

    RTE_LOG(INFO, NETIF, "%s(%d) used to redirect icmp packets\n",
        current_worker->name, current_worker->cpu_id);
    g_icmp_redirect_lcore_id = current_worker->cpu_id;
}
#endif

static void worker_port_handler(vector_t tokens)
{
    assert(VECTOR_SIZE(tokens) >= 1);

    char *str;
    int ii;
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *queue_cfg = rte_malloc(NULL,
            sizeof(struct queue_conf_stream), RTE_CACHE_LINE_SIZE);
    if (!queue_cfg) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return;
    }

    for (ii = 0; ii < NETIF_MAX_QUEUES; ii++) {
        queue_cfg->tx_queues[ii] = NETIF_MAX_QUEUES;
        queue_cfg->rx_queues[ii] = NETIF_MAX_QUEUES;
        queue_cfg->isol_rxq_lcore_ids[ii] = NETIF_LCORE_ID_INVALID;
    }
    queue_cfg->isol_rxq_ring_sz = NETIF_ISOL_RXQ_RING_SZ_DEF;

    str = VECTOR_SLOT(tokens, 1);
    RTE_LOG(INFO, NETIF, "worker %s:%s queue config\n", current_worker->name, str);
    strncpy(queue_cfg->port_name, str, sizeof(queue_cfg->port_name));

    list_add(&queue_cfg->queue_list_node, &current_worker->port_list);
}

static void rx_queue_ids_handler(vector_t tokens)
{
    int ii, qid;
    char *str;
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *current_port = list_entry(current_worker->port_list.next,
            struct queue_conf_stream, queue_list_node);

    for (ii = 0; ii < VECTOR_SIZE(tokens) - 1; ii++) {
        str = VECTOR_SLOT(tokens, ii + 1);
        qid = atoi(str);
        if (qid < 0 || qid >= NETIF_MAX_QUEUES) {
            RTE_LOG(WARNING, NETIF, "invalid worker %s:%s rx_queue_id %s, using "
                    "default 0\n", current_worker->name, current_port->port_name, str);
            current_port->rx_queues[ii] = 0; /* using default worker config array */
        } else {
            RTE_LOG(WARNING, NETIF, "worker %s:%s rx_queue_id += %d\n",
                    current_worker->name, current_port->port_name, qid);
            current_port->rx_queues[ii] = qid;
        }
    }

    for ( ; ii < NETIF_MAX_QUEUES; ii++) /* unused space */
        current_port->rx_queues[ii] = NETIF_MAX_QUEUES;
}

static void tx_queue_ids_handler(vector_t tokens)
{
    int ii, qid;
    char *str;
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *current_port = list_entry(current_worker->port_list.next,
            struct queue_conf_stream, queue_list_node);

    for (ii = 0; ii < VECTOR_SIZE(tokens) - 1; ii++) {
        str = VECTOR_SLOT(tokens, ii + 1);
        qid = atoi(str);
        if (qid < 0 || qid >= NETIF_MAX_QUEUES) {
            RTE_LOG(WARNING, NETIF, "invalid worker %s:%s tx_queue_id %s, uisng "
                    "default 0\n", current_worker->name, current_port->port_name, str);
            current_port->tx_queues[ii] = 0; /* using default worker config array */
        } else {
            RTE_LOG(WARNING, NETIF, "worker %s:%s tx_queue_id += %d\n",
                    current_worker->name, current_port->port_name, qid);
            current_port->tx_queues[ii] = qid;
        }
    }

    for ( ; ii < NETIF_MAX_QUEUES; ii++) /* unused space */
        current_port->tx_queues[ii] = NETIF_MAX_QUEUES;
}

static void isol_rx_cpu_ids_handler(vector_t tokens)
{
    int ii, cid;
    char *str = set_value(tokens);
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *current_port = list_entry(current_worker->port_list.next,
            struct queue_conf_stream, queue_list_node);

    for (ii = 0; ii < VECTOR_SIZE(tokens) - 1; ii++) {
        str = VECTOR_SLOT(tokens, ii + 1);
        cid = atoi(str);
        if (cid <= 0 || cid >= DPVS_MAX_LCORE) {
            RTE_LOG(WARNING, NETIF, "invalid worker %s:%s:isol_rx_cpu_ids[%d] %s\n",
                    current_worker->name, current_port->port_name, ii, str);
            current_port->isol_rxq_lcore_ids[ii] = NETIF_LCORE_ID_INVALID;
        } else {
            RTE_LOG(INFO, NETIF, "worker %s:%s:isol_rx_cpu_ids[%d] = %d\n",
                    current_worker->name, current_port->port_name, ii, cid);
            current_port->isol_rxq_lcore_ids[ii] = cid;
        }
    }
}

static void isol_rxq_ring_sz_handler(vector_t tokens)
{
    int isol_rxq_ring_sz;
    char *str = set_value(tokens);
    struct worker_conf_stream *current_worker = list_entry(worker_list.next,
            struct worker_conf_stream, worker_list_node);
    struct queue_conf_stream *current_port = list_entry(current_worker->port_list.next,
            struct queue_conf_stream, queue_list_node);

    assert(str);
    if (strspn(str, "0123456789") != strlen(str)) {
        RTE_LOG(WARNING, NETIF, "invalid worker %s:%s:isol_rxq_ring_sz %s,"
                " using default %d\n", current_worker->name, current_port->port_name,
                str, NETIF_ISOL_RXQ_RING_SZ_DEF);
        current_port->isol_rxq_ring_sz = NETIF_ISOL_RXQ_RING_SZ_DEF;
    } else {
        isol_rxq_ring_sz = atoi(str);
        RTE_LOG(INFO, NETIF, "worker %s:%s:isol_rxq_ring_sz = %d\n",
                current_worker->name, current_port->port_name, isol_rxq_ring_sz);
        current_port->isol_rxq_ring_sz = isol_rxq_ring_sz;
    }

    FREE_PTR(str);
}

void netif_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        netif_pktpool_nb_mbuf = NETIF_PKTPOOL_NB_MBUF_DEF;
        netif_pktpool_mbuf_cache = NETIF_PKTPOOL_MBUF_CACHE_DEF;
    }
    /* KW_TYPE_NORMAL keyword */
}

void install_netif_keywords(void)
{
    install_keyword_root("netif_defs", netif_defs_handler);
    install_keyword("pktpool_size", pktpool_size_handler, KW_TYPE_INIT);
    install_keyword("pktpool_cache", pktpool_cache_handler, KW_TYPE_INIT);
    install_keyword_root("worker_defs", worker_defs_handler);
    install_keyword("worker", worker_handler, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("type", worker_type_handler, KW_TYPE_INIT);
    install_keyword("cpu_id", cpu_id_handler, KW_TYPE_INIT);
#ifdef CONFIG_ICMP_REDIRECT_CORE
    install_keyword("icmp_redirect_core", cpu_icmp_redirect_handler, KW_TYPE_INIT);
#endif
    install_keyword("port", worker_port_handler, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("rx_queue_ids", rx_queue_ids_handler, KW_TYPE_INIT);
    install_keyword("tx_queue_ids", tx_queue_ids_handler, KW_TYPE_INIT);
    install_keyword("isol_rx_cpu_ids", isol_rx_cpu_ids_handler, KW_TYPE_INIT);
    install_keyword("isol_rxq_ring_sz", isol_rxq_ring_sz_handler, KW_TYPE_INIT);
    install_sublevel_end();
    install_sublevel_end();
}

void netif_cfgfile_init(void)
{
    INIT_LIST_HEAD(&worker_list);
}

static void netif_cfgfile_term(void)
{
    struct worker_conf_stream *worker_cfg, *worker_cfg_next;
    struct queue_conf_stream *queue_cfg, *queue_cfg_next;

    list_for_each_entry_safe(worker_cfg, worker_cfg_next, &worker_list,
            worker_list_node) {
        list_del(&worker_cfg->worker_list_node);
        list_for_each_entry_safe(queue_cfg, queue_cfg_next, &worker_cfg->port_list,
                queue_list_node) {
            list_del(&queue_cfg->queue_list_node);
            rte_free(queue_cfg);
        }
        rte_free(worker_cfg);
    }
}


#ifdef CONFIG_DPVS_NETIF_DEBUG
#include <arpa/inet.h>
#include <netinet/in.h>

static inline int parse_ether_hdr(struct rte_mbuf *mbuf, uint16_t port, uint16_t queue) {
    struct rte_ether_hdr *eth_hdr;
    char saddr[18], daddr[18];
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_ether_format_addr(saddr, sizeof(saddr), &eth_hdr->src_addr);
    rte_ether_format_addr(daddr, sizeof(daddr), &eth_hdr->dst_addr);
    RTE_LOG(INFO, NETIF, "[%s] lcore=%u port=%u queue=%u ethtype=%0x saddr=%s daddr=%s\n",
            __func__, rte_lcore_id(), port, queue, rte_be_to_cpu_16(eth_hdr->ether_type),
            saddr, daddr);
    return EDPVS_OK;
}

static inline int is_ipv4_pkt_valid(struct rte_ipv4_hdr *iph, uint32_t link_len)
{
    if (((iph->version_ihl) >> 4) != 4)
        return EDPVS_INVAL;
    if ((iph->version_ihl & 0xf) < 5)
        return EDPVS_INVAL;
    if (rte_cpu_to_be_16(iph->total_length) < sizeof(struct rte_ipv4_hdr))
        return EDPVS_INVAL;
    return EDPVS_OK;
}

__rte_unused static void parse_ipv4_hdr(struct rte_mbuf *mbuf, uint16_t port, uint16_t queue)
{
    char saddr[16], daddr[16];
    uint16_t lcore;
    struct rte_ipv4_hdr *iph;
    struct rte_udp_hdr *uh;

    iph = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    if (is_ipv4_pkt_valid(iph, mbuf->pkt_len) < 0)
        return;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) +
            (RTE_IPV4_HDR_IHL_MASK & iph->version_ihl) * sizeof(uint32_t));

    lcore = rte_lcore_id();
    if (!inet_ntop(AF_INET, &iph->src_addr, saddr, sizeof(saddr)))
        return;
    if (!inet_ntop(AF_INET, &iph->dst_addr, daddr, sizeof(daddr)))
        return;

    RTE_LOG(INFO, NETIF, "[%s] lcore=%u port=%u queue=%u ipv4_hl=%u tos=%u tot=%u "
            "id=%u ttl=%u prot=%u src=%s dst=%s sport=%04x|%u dport=%04x|%u\n",
            __func__, lcore, port, queue, RTE_IPV4_HDR_IHL_MASK & iph->version_ihl,
            iph->type_of_service, ntohs(iph->total_length),
            ntohs(iph->packet_id), iph->time_to_live, iph->next_proto_id, saddr, daddr,
            uh->src_port, ntohs(uh->src_port), uh->dst_port, ntohs(uh->dst_port));
    return;
}

__rte_unused static void pkt_send_back(struct rte_mbuf *mbuf, struct netif_port *port)
{
    struct rte_ether_hdr *ehdr;
    struct rte_ether_addr eaddr;
    ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    rte_ether_addr_copy(&ehdr->src_addr, &eaddr);
    rte_ether_addr_copy(&ehdr->dst_addr, &ehdr->src_addr);
    rte_ether_addr_copy(&eaddr, &ehdr->dst_addr);
    netif_xmit(mbuf, port);
}
#endif

/********************************************* mbufpool *******************************************/
struct rte_mempool *pktmbuf_pool[DPVS_MAX_SOCKET];

static inline void netif_pktmbuf_pool_init(void)
{
    int i;
    char poolname[32];
    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(poolname, sizeof(poolname), "mbuf_pool_%d", i);
        pktmbuf_pool[i] = rte_pktmbuf_pool_create(poolname, netif_pktpool_nb_mbuf,
                netif_pktpool_mbuf_cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE, i);
        if (!pktmbuf_pool[i])
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d", i);
    }
}

/******************************************* pkt-type *********************************************/
#define NETIF_PKT_TYPE_TABLE_BITS 8
#define NETIF_PKT_TYPE_TABLE_BUCKETS (1 << NETIF_PKT_TYPE_TABLE_BITS)
#define NETIF_PKT_TYPE_TABLE_MASK (NETIF_PKT_TYPE_TABLE_BUCKETS - 1)
/* Note: Lockless. pkt_type can only be registered on initialization stage,
 *       and unregistered on cleanup stage. Otherwise uncertain behavior may arise.
 */
static struct list_head pkt_type_tab[NETIF_PKT_TYPE_TABLE_BUCKETS];

static inline int pkt_type_tab_hashkey(uint16_t type)
{
    return type & NETIF_PKT_TYPE_TABLE_MASK;
}

static inline void netif_pkt_type_tab_init(void)
{
    int i;
    for (i = 0; i < NETIF_PKT_TYPE_TABLE_BUCKETS; i++)
        INIT_LIST_HEAD(&pkt_type_tab[i]);
}

int netif_register_pkt(struct pkt_type *pt)
{
    struct pkt_type *cur;
    int hash;
    if (unlikely(NULL == pt))
        return EDPVS_INVAL;

    hash = pkt_type_tab_hashkey(pt->type);
    list_for_each_entry(cur, &pkt_type_tab[hash], list) {
        if (cur->type == pt->type) {
            return EDPVS_EXIST;
        }
    }
    list_add_tail(&pt->list, &pkt_type_tab[hash]);
    return EDPVS_OK;
}

int netif_unregister_pkt(struct pkt_type *pt)
{
    struct pkt_type *cur;
    int hash;
    if (unlikely(NULL == pt))
        return EDPVS_INVAL;

    hash = pkt_type_tab_hashkey(pt->type);
    list_for_each_entry(cur, &pkt_type_tab[hash], list) {
        if (cur->type == pt->type) {
            list_del_init(&pt->list);
            return EDPVS_OK;
        }
    }
    return EDPVS_NOTEXIST;
}

static struct pkt_type *pkt_type_get(__be16 type, struct netif_port *port)
{
    struct pkt_type *pt;
    int hash;

    hash = pkt_type_tab_hashkey(type);
    list_for_each_entry(pt, &pkt_type_tab[hash], list) {
        if (pt->type == type && ((pt->port == NULL) || pt->port == port)) {
            return pt;
        }
    }
    return NULL;
}

/****************************************** lcore  conf ********************************************/
/* per-lcore statistics */
static struct netif_lcore_stats lcore_stats[DPVS_MAX_LCORE];
/* per-lcore isolated reception queues */
static struct list_head isol_rxq_tab[DPVS_MAX_LCORE];

/* worker configuration array */
static struct netif_lcore_conf lcore_conf[DPVS_MAX_LCORE];

static int isol_rxq_add(lcoreid_t cid, portid_t pid, queueid_t qid,
        unsigned rb_sz, struct netif_queue_conf *rxq);
static void isol_rxq_del(struct rx_partner *isol_rxq, bool force);

static void config_lcores(struct list_head *worker_list)
{
    int tk;
    int cpu_id_min, cpu_left, cpu_cnt;
    struct worker_conf_stream *worker, *worker_next, *worker_min;

    memset(lcore_conf, 0, sizeof(lcore_conf));

    cpu_cnt = cpu_left = list_elems(worker_list);
    list_for_each_entry_safe(worker, worker_next, worker_list, worker_list_node) {
        if (!strcmp(worker->type, "master")) {
            lcore_conf[worker->cpu_id].type = LCORE_ROLE_MASTER;
            list_move_tail(&worker->worker_list_node, worker_list);
            cpu_left--;
        }
        if (--cpu_cnt == 0)
            break;
    }

    while (cpu_left > 0) {
        cpu_id_min = DPVS_MAX_LCORE;
        worker_min = NULL;

        tk = 0;
        list_for_each_entry(worker, worker_list, worker_list_node) {
            if (cpu_id_min > worker->cpu_id) {
                cpu_id_min = worker->cpu_id;
                worker_min = worker;
            }
            if (++tk >= cpu_left)
                break;
        }
        assert(worker_min != NULL);

        if (!strncmp(worker_min->type, "slave", sizeof("slave")))
            lcore_conf[worker_min->cpu_id].type = LCORE_ROLE_FWD_WORKER;
        else if (!strncmp(worker_min->type, "kni", sizeof("kni")))
            lcore_conf[worker_min->cpu_id].type = LCORE_ROLE_KNI_WORKER;


        list_move_tail(&worker_min->worker_list_node, worker_list);
        cpu_left--;
    }
}

/* fast searching tables */
portid_t port2index[DPVS_MAX_LCORE][NETIF_MAX_PORTS];

static void port_index_init(void)
{
    int ii, jj;
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++)
        for (jj = 0; jj < NETIF_MAX_PORTS; jj++)
            port2index[ii][jj] = NETIF_PORT_ID_INVALID;
}

void netif_get_slave_lcores(uint8_t *nb, uint64_t *mask)
{
    int i = 0;
    uint64_t slave_lcore_mask = 0L;
    uint8_t slave_lcore_nb = 0;

    while (i < DPVS_MAX_LCORE) {
        /* LCORE_ROLE_KNI_WORKER should be excluded,
         * as ports is configured for KNI core. */
        if (lcore_conf[i].type == LCORE_ROLE_FWD_WORKER) {
            slave_lcore_nb++;
            slave_lcore_mask |= (1L << i);
        }
        i++;
    }

    if (nb)
        *nb = slave_lcore_nb;
    if (mask)
        *mask = slave_lcore_mask;
}

static void netif_get_isol_rx_lcores(uint8_t *nb, uint64_t *mask)
{
    lcoreid_t cid;
    uint64_t isol_lcore_mask = 0L;
    uint8_t isol_lcore_nb = 0;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!list_empty(&isol_rxq_tab[cid])) {
            isol_lcore_nb++;
            isol_lcore_mask |= (1L << cid);
        }
    }

    if (nb)
        *nb = isol_lcore_nb;
    if (mask)
        *mask = isol_lcore_mask;
}

static void build_lcore_index(void)
{
    int cid, idx = 0;

    g_lcore_index2id[idx++] = rte_get_main_lcore();

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++)
        if (g_lcore_role[cid] == LCORE_ROLE_FWD_WORKER)
            g_lcore_index2id[idx++] = cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++)
        if (g_lcore_role[cid] == LCORE_ROLE_ISOLRX_WORKER)
            g_lcore_index2id[idx++] = cid;
    g_lcore_num = idx;

    for (idx = 0; idx < DPVS_MAX_LCORE; idx++) {
        cid = g_lcore_index2id[idx];
        if (cid >= 0 && cid < DPVS_MAX_LCORE)
            g_lcore_id2index[cid] = idx;
    }
}

static inline void dump_lcore_role(void)
{
    dpvs_lcore_role_t role;
    lcoreid_t cid;
    char bufs[LCORE_ROLE_MAX+1][1024];
    char results[sizeof bufs];

    for (role = 0; role < LCORE_ROLE_MAX; role++)
        snprintf(bufs[role], sizeof(bufs[role]), "\t%s: ",
                dpvs_lcore_role_str(role));

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        role = g_lcore_role[cid];
        snprintf(&bufs[role][strlen(bufs[role])], sizeof(bufs[role])
                    - strlen(bufs[role]), "%-4d", cid);
    }

    snprintf(results, sizeof(results), "%s", bufs[0]);
    for (role = 1; role < LCORE_ROLE_MAX; role++) {
        strncat(results, "\n", sizeof(results) - strlen(results) - 1);
        strncat(results, bufs[role], sizeof(results) - strlen(results) - 1);
    }

    RTE_LOG(INFO, NETIF, "LCORE ROLES:\n%s\n", results);
}

static void lcore_role_init(void)
{
    int cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++)
        if (!rte_lcore_is_enabled(cid))
            /* invalidate the disabled cores */
            g_lcore_role[cid] = LCORE_ROLE_MAX;

    cid = rte_get_main_lcore();

    assert(g_lcore_role[cid] == LCORE_ROLE_IDLE);
    g_lcore_role[cid] = LCORE_ROLE_MASTER;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (lcore_conf[cid].type == LCORE_ROLE_FWD_WORKER ||
            lcore_conf[cid].type == LCORE_ROLE_KNI_WORKER) {
            g_lcore_role[cid] = lcore_conf[cid].type;
        }
    }

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!list_empty(&isol_rxq_tab[cid])) {
            assert(g_lcore_role[cid] == LCORE_ROLE_IDLE);
            g_lcore_role[cid] =  LCORE_ROLE_ISOLRX_WORKER;
        }
    }

    build_lcore_index();
    dump_lcore_role();
}

static inline void netif_copy_lcore_stats(struct netif_lcore_stats *stats)
{
    lcoreid_t cid;
    cid = rte_lcore_id();
    assert(cid < DPVS_MAX_LCORE);
    rte_memcpy(stats, &lcore_stats[cid], sizeof(struct netif_lcore_stats));
}

#define LCONFCHK_MARK                       255
#define LCONFCHK_OK                         0
#define LCONFCHK_REPEATED_RX_QUEUE_ID       -2
#define LCONFCHK_REPEATED_TX_QUEUE_ID       -3
#define LCONFCHK_DISCONTINUOUS_QUEUE_ID     -4
#define LCONFCHK_PORT_NOT_ENOUGH            -5
#define LCONFCHK_INCORRECT_TX_QUEUE_NUM     -6
#define LCONFCHK_NO_SLAVE_LCORES            -7

static int check_lcore_conf(int lcores, const struct netif_lcore_conf *lcore_conf)
{
    return LCONFCHK_OK;
}

static inline void lcore_stats_burst(struct netif_lcore_stats *stats,
                                     size_t len)
{
    stats->pktburst++;

    if (0 == len) {
        stats->zpktburst++;
        stats->z2hpktburst++;
    } else if (len <= NETIF_MAX_PKT_BURST/2) {
        stats->z2hpktburst++;
    } else if (len < NETIF_MAX_PKT_BURST) {
        stats->h2fpktburst++;
    } else {
        stats->h2fpktburst++;
        stats->fpktburst++;
    }
}

static inline void isol_rxq_init(void)
{
    int i;
    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        INIT_LIST_HEAD(&isol_rxq_tab[i]);
    }
}

/* call me at initialization before lcore loop */
static int isol_rxq_add(lcoreid_t cid, portid_t pid, queueid_t qid,
                        unsigned rb_sz, struct netif_queue_conf *rxq)
{
    assert(cid <= DPVS_MAX_LCORE);
    int rb_sz_r;
    struct rx_partner *isol_rxq;
    struct rte_ring *rb;
    char name[32];

    isol_rxq = rte_zmalloc("isol_rxq", sizeof(struct rx_partner), 0);
    if (unlikely(!isol_rxq))
        return EDPVS_NOMEM;

    is_power2(rb_sz, 0, &rb_sz_r);
    memset(name, 0, 32);
    snprintf(name, sizeof(name) - 1, "isol_rxq_c%dp%dq%d", cid, pid, qid);

    rb = rte_ring_create(name, rb_sz_r, rte_socket_id(),
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (unlikely(!rb))
        return EDPVS_DPDKAPIFAIL;

    isol_rxq->cid = cid;
    isol_rxq->pid = pid;
    isol_rxq->qid = qid;
    isol_rxq->rxq = rxq;
    isol_rxq->rb = rb;

    list_add(&isol_rxq->lnode, &isol_rxq_tab[cid]);
    rxq->isol_rxq = isol_rxq;

    return EDPVS_OK;
}

/* call me at termination */
__rte_unused
static void isol_rxq_del(struct rx_partner *isol_rxq, bool force)
{
    assert(isol_rxq);

    /* stop recieving packets */
    list_del(&isol_rxq->lnode);

    if (force) {
        /* dequeue all packets in the ring and drop them */
        struct rte_mbuf *mbuf;
        while (!rte_ring_dequeue(isol_rxq->rb, (void **)&mbuf))
            rte_pktmbuf_free(mbuf);
    } else {
        /* wait until all packets in the ring processed */
        while (!rte_ring_empty(isol_rxq->rb))
            ;
    }

    /* remove isolate cpu packet reception */
    isol_rxq->rxq->isol_rxq = NULL;

    rte_ring_free(isol_rxq->rb);
    rte_free(isol_rxq);

    isol_rxq = NULL;
}

inline static void recv_on_isol_lcore(void *dump)
{
    struct rx_partner *isol_rxq;
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    unsigned int rx_len, qspc;
    int i, res;
    lcoreid_t cid = rte_lcore_id();

    list_for_each_entry(isol_rxq, &isol_rxq_tab[cid], lnode) {
        assert(isol_rxq->cid == cid);
again:
        rx_len = rte_eth_rx_burst(isol_rxq->pid, isol_rxq->qid,
                mbufs, NETIF_MAX_PKT_BURST);
        /* It is safe to reuse lcore_stats for isolate recieving. Isolate recieving
         * always lays on different lcores from packet processing. */
        lcore_stats_burst(&lcore_stats[cid], rx_len);

        if (rx_len == 0)
            continue;

        lcore_stats[cid].ipackets += rx_len;
        for (i = 0; i < rx_len; i++)
            lcore_stats[cid].ibytes += mbufs[i]->pkt_len;

        res = rte_ring_enqueue_bulk(isol_rxq->rb, (void *const * )mbufs, rx_len, &qspc);
        if (res < rx_len) {
            RTE_LOG(WARNING, NETIF, "%s [%d]: %d packets failed to enqueue,"
                    " space avail: %u\n", __func__, cid, rx_len - res, qspc);
            lcore_stats[cid].dropped += (rx_len - res);
            for (i = res; i < rx_len; i++)
                rte_pktmbuf_free(mbufs[i]);
        }

        if (rx_len >= NETIF_MAX_PKT_BURST && rte_ring_free_count(isol_rxq->rb) >= NETIF_MAX_PKT_BURST)
            goto again;
    }
}

inline static bool is_isol_rxq_lcore(lcoreid_t cid)
{
    assert(cid < DPVS_MAX_LCORE);

    return !list_empty(&isol_rxq_tab[cid]);
}

inline static bool is_kni_lcore(lcoreid_t cid)
{
    assert(cid < DPVS_MAX_LCORE);

    return g_kni_lcore_id == cid;
}

bool netif_lcore_is_fwd_worker(lcoreid_t cid)
{
    if (cid > DPVS_MAX_LCORE)
        return false;

    return (lcore_conf[cid].type  ==
            LCORE_ROLE_FWD_WORKER) ? true : false;
}

static inline uint16_t netif_rx_burst(portid_t pid, struct netif_queue_conf *qconf)
{
    struct rte_mbuf *mbuf;
    int nrx = 0;

    if (qconf->isol_rxq) {
        /* note API rte_ring_dequeue_bulk of dpdk-16.07 is not suitable, replace with
         * its bulk version after upgrading to new dpdk version */
        while (0 == rte_ring_dequeue(qconf->isol_rxq->rb, (void**)&mbuf)) {
            qconf->mbufs[nrx++] = mbuf;
            if (unlikely(nrx >= NETIF_MAX_PKT_BURST))
                break;
        }

        /* Shoul we integrate statistics of isolated recieve lcore into packet
         * processing lcore ? No! we just leave the work to tools */
    } else {
        nrx = rte_eth_rx_burst(pid, qconf->id, qconf->mbufs, NETIF_MAX_PKT_BURST);
    }

    qconf->len = nrx;
    return nrx;
}

/* just for print */
struct port_queue_lcore_map {
    portid_t pid;
    char mac_addr[18];
    queueid_t rx_qid[NETIF_MAX_QUEUES];
    queueid_t tx_qid[NETIF_MAX_QUEUES];
};
portid_t netif_max_pid;
queueid_t netif_max_qid;
struct port_queue_lcore_map pql_map[NETIF_MAX_PORTS];

int netif_print_port_queue_conf(portid_t pid, char *buf, int *len)
{
    int i, j;
    char line[1024], tbuf[32], tbuf2[32];
    struct port_queue_lcore_map *pmap = NULL;
    int left_len;

    if (unlikely(!buf || !len || *len <= 0))
        return EDPVS_INVAL;

    for (i = 0; i <= netif_max_pid; i++) {
        if (pql_map[i].pid == pid) {
            pmap = &pql_map[i];
            break;
        }
    }
    if (!pmap) {
        RTE_LOG(WARNING, NETIF, "[%s] no queue confiugred on dpdk%d\n", __func__, pid);
        return EDPVS_NOTEXIST;
    }

    memset(buf, 0, *len);
    snprintf(buf, *len, "configured queues on dpdk%d (%s):\n    %-12s%-12s%-12s\n",
            pmap->pid, pmap->mac_addr, "QUEUE", "RX", "TX");
    for (j = 0; pmap->rx_qid[j] != NETIF_PORT_ID_INVALID || pmap->tx_qid[j] != NETIF_PORT_ID_INVALID; j++) {
        snprintf(tbuf, sizeof(tbuf), "rx%d/tx%d", j, j);
        snprintf(line, sizeof(line), "    %-12s", tbuf);
        if (pmap->rx_qid[j] != NETIF_PORT_ID_INVALID) {
            snprintf(tbuf2, sizeof(tbuf2), "cpu%d", pmap->rx_qid[j]);
            snprintf(tbuf, sizeof(tbuf), "%-12s", tbuf2);
            strncat(line, tbuf, sizeof(line) - strlen(line));
        } else {
            snprintf(tbuf, sizeof(tbuf), "%-12s", "--");
            strncat(line, tbuf, sizeof(line) - strlen(line));
        }
        if (pmap->tx_qid[j] != NETIF_PORT_ID_INVALID) {
            snprintf(tbuf, sizeof(tbuf), "cpu%d", pmap->tx_qid[j]);
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);
        } else {
            snprintf(tbuf, sizeof(tbuf), "%-12s", "--");
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);
        }
        strncat(line, "\n", sizeof(line) - strlen(line));

        left_len = *len - strlen(buf) - 1;
        if (left_len <= 0) {
            RTE_LOG(WARNING, NETIF, "[%s] buffer not enough\n", __func__);
            *len = strlen(buf) + 1;
            return EDPVS_INVAL;
        }
        strncat(buf, line, left_len);
    }

    *len = strlen(buf) + 1;
    return EDPVS_OK;
}

int netif_print_lcore_queue_conf(lcoreid_t cid, char *buf, int *len, bool has_title)
{
    int i;
    struct netif_port *port;
    struct netif_lcore_conf *plcore = NULL;
    char line[1024], tbuf[32], tbuf2[32];
    int left_len;

    if (unlikely(!buf || !len || *len <= 0))
        return EDPVS_INVAL;

    if (unlikely(rte_get_main_lcore() == cid)) {
        buf[0] = '\0';
        *len = 0;
        return EDPVS_OK;
    }

    i = 0;
    plcore = &lcore_conf[cid];
    if (!plcore->nports) {
        RTE_LOG(WARNING, NETIF, "[%s] cpu%d has no port-queue configured", __func__, cid);
        return EDPVS_NOTEXIST;
    }

    memset(buf, 0, *len);
    for (i = 0; i < plcore->nports; i++) {
        port = netif_port_get(plcore->pqs[i].id);
        assert(port);
        memset(line, 0, sizeof(line));
        if (has_title) {
            snprintf(tbuf, sizeof(tbuf), "cpu%d", cid);
            snprintf(line, sizeof(line), "%-12s", tbuf);
        }

        snprintf(tbuf2, sizeof(tbuf2), "%s:rx%d",
                    port->name, plcore->pqs[i].rxq.id);
        snprintf(tbuf, sizeof(tbuf), "%-16s", tbuf2);
        strncat(line, tbuf, sizeof(line) - strlen(line) -1);

        snprintf(tbuf2, sizeof(tbuf2), "%s:tx%d",
                    port->name, plcore->pqs[i].txq.id);
        snprintf(tbuf, sizeof(tbuf), "%-16s", tbuf2);
        strncat(line, tbuf, sizeof(line) - strlen(line) - 1);

        left_len = *len - strlen(buf) - 1;
        if (left_len <= 0) {
            RTE_LOG(WARNING, NETIF, "[%s] buffer not enough\n", __func__);
            *len = strlen(buf) + 1;
            return EDPVS_INVAL;
        }
        strncat(buf, line, left_len);
    }

    *len = strlen(buf) + 1;
    return EDPVS_OK;
}

static int netif_print_isol_lcore_conf(lcoreid_t cid, char *buf, int *len, bool has_title)
{
    int left_len;
    char tbuf[32], tbuf2[32];
    struct netif_port *port;
    struct rx_partner *p_curr, *p_next;

    assert(buf && len);
    if (!is_isol_rxq_lcore(cid)) {
        buf[0] = '\0';
        *len = 0;
        return EDPVS_OK;
    }

    memset(buf, 0, *len);
    left_len = *len - 1;

    if (has_title)
        snprintf(buf, left_len, "isol_rxqs on cpu%d: \n", cid);

    list_for_each_entry_safe(p_curr, p_next, &isol_rxq_tab[cid], lnode) {
        assert(p_curr->cid == cid);
        memset(tbuf, 0, sizeof(tbuf));
        memset(tbuf2, 0, sizeof(tbuf2));

        port = netif_port_get(p_curr->pid);
        if (!port)
            return EDPVS_INVAL;
        snprintf(tbuf2, sizeof(tbuf2) - 1, "%s:rx%d(%d/%d)",
                port->name, p_curr->qid,
                rte_ring_count(p_curr->rb),
                rte_ring_free_count(p_curr->rb));
        snprintf(tbuf, sizeof(tbuf) - 1, "%-32s", tbuf2);

        left_len = *len - strlen(buf) - 1;
        strncat(buf, tbuf, left_len);
    }

    *len = strlen(buf) + 1;
    return EDPVS_OK;
}

static inline void netif_tx_burst(lcoreid_t cid, portid_t pid)
{
    int ntx;
    struct netif_queue_conf *txq;
    unsigned i = 0;
    struct rte_mbuf *mbuf_copied = NULL;
    struct netif_port *dev = NULL;

    assert(cid < DPVS_MAX_LCORE);
    txq = &lcore_conf[cid].pqs[port2index[cid][pid]].txq;
    if (0 == txq->len)
        return;

    dev = netif_port_get(pid);
    if (dev && (dev->flag & NETIF_PORT_FLAG_FORWARD2KNI)) {
        for (; i < txq->len; i++) {
            if (NULL == (mbuf_copied = mbuf_copy(txq->mbufs[i], pktmbuf_pool[dev->socket])))
                RTE_LOG(WARNING, NETIF, "%s: fail to copy outbound mbuf into kni\n", __func__);
            else
                kni_ingress(mbuf_copied, dev);
        }
    }

    ntx = rte_eth_tx_burst(pid, txq->id, txq->mbufs, txq->len);
    lcore_stats[cid].opackets += ntx;
    /* do not calculate obytes here in consideration of efficency */
    if (unlikely(ntx < txq->len)) {
        RTE_LOG(INFO, NETIF, "fail to send %d of %d packets on dpdk port %d txq %d\n",
                txq->len - ntx, txq->len, pid, txq->id);
        lcore_stats[cid].dropped += txq->len - ntx;
        do {
            rte_pktmbuf_free(txq->mbufs[ntx]);
        } while (++ntx < txq->len);
    }
}

/* Call me on MASTER lcore */
static inline lcoreid_t get_master_xmit_lcore(void)
{
    static int cid = 0;
    while(true) {
        cid++;
        if (cid >= DPVS_MAX_LCORE) {
            cid = 0;
        }
        if (g_slave_lcore_mask & (1L << cid)) {
            return cid;
        }
    }
}

struct master_xmit_msg_data {
    struct rte_mbuf *mbuf;
    struct netif_port *dev;
};

static int msg_type_master_xmit_cb(struct dpvs_msg *msg)
{
    struct master_xmit_msg_data *data;
    if (unlikely(NULL == msg || msg->len != sizeof(struct master_xmit_msg_data)))
        return EDPVS_INVAL;

    data = (struct master_xmit_msg_data*)(msg->data);
    if (likely(msg->type == MSG_TYPE_MASTER_XMIT && msg->mode == DPVS_MSG_UNICAST)) {
        //RTE_LOG(DEBUG, NETIF, "Xmit master packet on Slave lcore%u %s\n",
        //        rte_lcore_id(), data->dev->name);
        //fflush(stdout);
        return netif_xmit(data->mbuf, data->dev);
    }

    return EDPVS_INVAL;
}

/* master_xmit_msg should be registered on all slave lcores */
int netif_register_master_xmit_msg(void)
{
    int ret;
    unsigned ii;
    struct dpvs_msg_type mt;
    uint64_t slave_lcore_mask;
    uint8_t slave_lcore_nb;

    memset(&mt, 0, sizeof(mt));
    mt.type = MSG_TYPE_MASTER_XMIT;
    mt.mode = DPVS_MSG_UNICAST;
    mt.prio = MSG_PRIO_HIGH;
    mt.unicast_msg_cb = msg_type_master_xmit_cb;

    netif_get_slave_lcores(&slave_lcore_nb, &slave_lcore_mask);
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if(!(slave_lcore_mask & (1UL << ii)))
            continue;
        mt.cid = ii;
        if (unlikely((ret = msg_type_register(&mt)) < 0)) {
            rte_exit(EXIT_FAILURE, "[%s] fail to register master_xmit_msg,"
                    " exiting ...\n", __func__);
            return ret;
        }
        RTE_LOG(DEBUG, NETIF, "[%s] master_xmit_msg registered on lcore #%d\n",
                __func__, ii);
    }

    return EDPVS_OK;
}

static inline int validate_xmit_mbuf(struct rte_mbuf *mbuf,
                                     const struct netif_port *dev)
{
    int err = EDPVS_OK;

    return err;
}

int netif_hard_xmit(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    lcoreid_t cid;
    int pid;
    struct netif_queue_conf *txq;
    struct netif_ops *ops;
    int ret = EDPVS_OK;

    if (unlikely(NULL == mbuf || NULL == dev)) {
        if (mbuf)
            rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    ops = dev->netif_ops;
    if (ops && ops->op_xmit)
        return ops->op_xmit(mbuf, dev);

    /* send pkt on current lcore */
    cid = rte_lcore_id();

    if (likely(mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM))
        mbuf->l2_len = sizeof(struct rte_ether_hdr);

    if (rte_get_main_lcore() == cid) { // master thread
        struct dpvs_msg *msg;
        struct master_xmit_msg_data msg_data;

        /* NOTE: Ctrl plane send pkts via Data plane, thus no packets are sent on Master lcore.
         * The statistics here is to find out how many packets are sent on Ctrl plane. */
        lcore_stats[cid].opackets++;
        lcore_stats[cid].obytes += mbuf->pkt_len;

        msg_data.mbuf = mbuf;
        msg_data.dev = dev;
        msg = msg_make(MSG_TYPE_MASTER_XMIT, 0, DPVS_MSG_UNICAST, rte_get_main_lcore(),
                sizeof(struct master_xmit_msg_data), &msg_data);
        if (unlikely(NULL == msg)) {
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOMEM;
        }

        cid = get_master_xmit_lcore();
        if (unlikely(ret = msg_send(msg, cid, DPVS_MSG_F_ASYNC, NULL))) {
            RTE_LOG(WARNING, NETIF, "[%s] Send master_xmit_msg(%d) failed\n", __func__, cid);
            rte_pktmbuf_free(mbuf);
        }
        msg_destroy(&msg);
        return ret;
    }

    if (unlikely((ret = validate_xmit_mbuf(mbuf, dev)) != EDPVS_OK)) {
        RTE_LOG(WARNING, NETIF, "%s: validate_xmit_mbuf error\n", __func__);
        rte_pktmbuf_free(mbuf);
        return ret;
    }

    /* port id is determined by routing */
    pid = dev->id;
    txq = &lcore_conf[cid].pqs[port2index[cid][pid]].txq;
    /* No space left in txq mbufs, transmit cached mbufs immediately */
    if (unlikely(txq->len == NETIF_MAX_PKT_BURST)) {
        netif_tx_burst(cid, pid);
        txq->len = 0;
    }

#ifdef CONFIG_DPVS_NETIF_DEBUG
    if ((dev->flag & NETIF_PORT_FLAG_TX_MBUF_FAST_FREE) && txq->pktpool) {
        if (txq->pktpool != mbuf->pool) {
            RTE_LOG(ERR, NETIF, "%s:txq%d pktmbuf pool changed: %s->%s, please disable tx_mbuf_fast_free\n",
                    dev->name, txq->id, txq->pktpool->name, mbuf->pool->name);
            txq->pktpool = mbuf->pool;
        }
    } else {
        txq->pktpool = mbuf->pool;
    }
#endif

    lcore_stats[cid].obytes += mbuf->pkt_len;
    txq->mbufs[txq->len] = mbuf;
    txq->len++;

    /* Cached mbufs transmit later in job `lcore_job_xmit` */

    return EDPVS_OK;
}

int netif_xmit(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    int ret = EDPVS_OK;
    uint16_t mbuf_refcnt;

    if (unlikely(NULL == mbuf || NULL == dev)) {
        if (mbuf)
            rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    if (mbuf->port != dev->id)
        mbuf->port = dev->id;

    /* assert for possible double free */
    mbuf_refcnt = rte_mbuf_refcnt_read(mbuf);
    assert((mbuf_refcnt >= 1) && (mbuf_refcnt <= 64));

    if (dev->flag & NETIF_PORT_FLAG_TC_EGRESS) {
        mbuf = tc_hook(netif_tc(dev), mbuf, TC_HOOK_EGRESS, &ret);
        if (!mbuf)
            return ret;
    }

    return netif_hard_xmit(mbuf, dev);
}

static inline eth_type_t eth_type_parse(const struct rte_ether_hdr *eth_hdr,
                                        const struct netif_port *dev)
{
    if (eth_addr_equal(&dev->addr, &eth_hdr->dst_addr))
        return ETH_PKT_HOST;

    if (rte_is_multicast_ether_addr(&eth_hdr->dst_addr)) {
        if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr))
            return ETH_PKT_BROADCAST;
        else
            return ETH_PKT_MULTICAST;
    }

    return ETH_PKT_OTHERHOST;
}

int netif_rcv(struct netif_port *dev, __be16 eth_type, struct rte_mbuf *mbuf)
{
    struct pkt_type *pt;
    assert(dev && mbuf && mbuf->port <= NETIF_MAX_PORTS);

    pt = pkt_type_get(eth_type, dev);
    if (!pt)
        return EDPVS_KNICONTINUE;

    return pt->func(mbuf, dev);
}

static int netif_deliver_mbuf(struct netif_port *dev, lcoreid_t cid,
                  struct rte_mbuf *mbuf, bool pkts_from_ring)
{
    int ret = EDPVS_OK;
    struct rte_ether_hdr *eth_hdr;

    assert(mbuf->port <= NETIF_MAX_PORTS);
    assert(dev != NULL);

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    /* reuse mbuf.packet_type, it was RTE_PTYPE_XXX */
    mbuf->packet_type = eth_type_parse(eth_hdr, dev);

    /*
     * In NETIF_PORT_FLAG_FORWARD2KNI mode.
     * All packets received are deep copied and sent to KNI
     * for the purpose of capturing forwarding packets.Since the
     * rte_mbuf will be modified in the following procedure,
     * we should use mbuf_copy instead of rte_pktmbuf_clone.
     */
    if (dev->flag & NETIF_PORT_FLAG_FORWARD2KNI) {
        struct rte_mbuf *mbuf_copied = mbuf_copy(mbuf, pktmbuf_pool[dev->socket]);
        if (likely(mbuf_copied != NULL))
            kni_ingress(mbuf_copied, dev);
        else
            RTE_LOG(WARNING, NETIF, "%s: failed to copy mbuf for kni\n", __func__);
    }

    if (!pkts_from_ring && (dev->flag & NETIF_PORT_FLAG_TC_INGRESS)) {
        mbuf = tc_hook(netif_tc(dev), mbuf, TC_HOOK_INGRESS, &ret);
        if (!mbuf)
            return ret;
    }

    return netif_rcv_mbuf(dev, cid, mbuf, pkts_from_ring);
}

int netif_rcv_mbuf(struct netif_port *dev, lcoreid_t cid, struct rte_mbuf *mbuf, bool pkts_from_ring)
{
    struct rte_ether_hdr *eth_hdr;
    struct pkt_type *pt;
    int err;
    uint16_t data_off;
    bool forward2kni;
    nsid_t nsid = dev->nsid;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    /*
     * do not drop pkt to other hosts (ETH_PKT_OTHERHOST)
     * since virtual devices may have different MAC with
     * underlying device.
     */

    /*
     * drop VLAN
     */
    if (eth_hdr->ether_type == htons(ETH_P_8021Q)) {
        goto drop;
    }

    forward2kni = (dev->flag & NETIF_PORT_FLAG_FORWARD2KNI) ? true : false;
    pt = pkt_type_get(eth_hdr->ether_type, dev);
    if (NULL == pt) {
        if (!forward2kni) {
            kni_ingress(mbuf, dev);
            goto done;
        }
        goto drop;
    }

    /* clone arp pkt to every queue */
    if (unlikely(pt->type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP) && !pkts_from_ring)) {
        uint8_t i;
        struct rte_arp_hdr *arp;
        struct rte_mbuf *mbuf_clone;

        arp = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
        if (rte_be_to_cpu_16(arp->arp_opcode) == RTE_ARP_OP_REPLY) {
            for (i = 0; i < DPVS_MAX_LCORE; i++) {
                if ((i == cid) || (!is_lcore_id_fwd(i))
                     || (i == rte_get_main_lcore()))
                    continue;
                /* rte_pktmbuf_clone will not clone pkt.data, just copy pointer! */
                mbuf_clone = rte_pktmbuf_clone(mbuf, pktmbuf_pool[dev->socket]);
                if (unlikely(!mbuf_clone)) {
                    RTE_LOG(WARNING, NETIF, "%s arp reply mbuf clone failed on lcore %d\n",
                            __func__, i);
                    continue;
                }
                err = rte_ring_enqueue(arp_ring[nsid][i], mbuf_clone);
                if (unlikely(-EDQUOT == err)) {
                    RTE_LOG(WARNING, NETIF, "%s: arp ring of lcore %d quota exceeded\n",
                            __func__, i);
                } else if (err < 0) {
                    RTE_LOG(WARNING, NETIF, "%s: arp ring of lcore %d enqueue failed\n",
                            __func__, i);
                    rte_pktmbuf_free(mbuf_clone);
                }
            }
        }
    }

    mbuf->l2_len = sizeof(struct rte_ether_hdr);

    /* Remove ether_hdr at the beginning of an mbuf */
    data_off = mbuf->data_off;
    if (unlikely(NULL == rte_pktmbuf_adj(mbuf, sizeof(struct rte_ether_hdr))))
        goto drop;

    err = pt->func(mbuf, dev);

    if (err == EDPVS_KNICONTINUE) {
        if (pkts_from_ring || forward2kni)
            goto slient_free;
        if (unlikely(NULL == rte_pktmbuf_prepend(mbuf, (mbuf->data_off - data_off))))
            goto drop;
        kni_ingress(mbuf, dev);
    }

done:
    if (!pkts_from_ring) {
        lcore_stats[cid].ibytes += mbuf->pkt_len;
        lcore_stats[cid].ipackets++;
    }
    return EDPVS_OK;

drop:
    lcore_stats[cid].dropped++;
slient_free:
    rte_pktmbuf_free(mbuf);
    return EDPVS_DROP;
}

static int netif_arp_ring_init(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
    nsid_t nsid;
    uint8_t cid;

    socket_id = rte_socket_id();
    for (nsid = 0; nsid < DPVS_MAX_NETNS; nsid++)
        for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
            snprintf(name_buf, RTE_RING_NAMESIZE, "arp_ring_ns%d_c%d", nsid, cid);
            arp_ring[nsid][cid] = rte_ring_create(name_buf, ARP_RING_SIZE, socket_id, RING_F_SC_DEQ);

            if (arp_ring[nsid][cid] == NULL)
                rte_panic("create ring:%s failed!\n", name_buf);
        }

    return EDPVS_OK;
}

void lcore_process_packets(struct rte_mbuf **mbufs, lcoreid_t cid, uint16_t count, bool pkts_from_ring)
{
    int i, t;

    /* prefetch packets */
    for (t = 0; t < count && t < NETIF_PKT_PREFETCH_OFFSET; t++)
        rte_prefetch0(rte_pktmbuf_mtod(mbufs[t], void *));

    /* L2 filter */
    for (i = 0; i < count; i++) {
        struct rte_mbuf *mbuf = mbufs[i];
        struct netif_port *dev = netif_port_get(mbuf->port);

        if (unlikely(!dev)) {
            rte_pktmbuf_free(mbuf);
            lcore_stats[cid].dropped++;
            continue;
        }

        mbuf->tx_offload = 0; /* reset l2_len, l3_len, l4_len, ... */

        if (t < count) {
            rte_prefetch0(rte_pktmbuf_mtod(mbufs[t], void *));
            t++;
        }

        /* handler should free mbuf */
        netif_deliver_mbuf(dev, cid, mbuf, pkts_from_ring);
    }
}

static void lcore_process_arp_ring(nsid_t nsid, lcoreid_t cid)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;

    nb_rb = rte_ring_dequeue_burst(arp_ring[nsid][cid], (void**)mbufs, NETIF_MAX_PKT_BURST, NULL);

    if (nb_rb > 0) {
        lcore_process_packets(mbufs, cid, nb_rb, 1);
    }
}

static void lcore_process_redirect_ring(lcoreid_t cid)
{
    dp_vs_redirect_ring_proc(cid);
}

static void lcore_job_recv_fwd(void *arg)
{
    int i;
    portid_t pid;
    lcoreid_t cid;
    nsid_t nsid;
    struct netif_queue_conf *qconf;

    cid = rte_lcore_id();
    assert(DPVS_MAX_LCORE > cid);
    
    struct netif_lcore_conf *local_lcore_conf = &lcore_conf[cid];
    for (i = 0; i < local_lcore_conf->nports; i++) {
        pid = local_lcore_conf->pqs[i].id;
        assert(pid <= phy_pid_end);
        nsid = local_lcore_conf->pqs[i].nsid;

        qconf = &local_lcore_conf->pqs[i].rxq;

        lcore_process_arp_ring(nsid, cid);
        lcore_process_redirect_ring(cid);
        qconf->len = netif_rx_burst(pid, qconf);

        lcore_stats_burst(&lcore_stats[cid], qconf->len);

        lcore_process_packets(qconf->mbufs, cid, qconf->len, 0);
    }
}

static void lcore_job_xmit(void *args)
{
    int i;
    lcoreid_t cid;
    portid_t pid;
    struct netif_queue_conf *qconf;

    cid = rte_lcore_id();
    struct netif_lcore_conf *local_lcore_conf = &lcore_conf[cid];
    for (i = 0; i < local_lcore_conf->nports; i++) {
        pid = local_lcore_conf->pqs[i].id;
#ifdef CONFIG_DPVS_NETIF_DEBUG
        if (unlikely(pid >= dpvs_rte_eth_dev_count())) {
            RTE_LOG(DEBUG, NETIF, "[%s] No enough NICs\n", __func__);
            continue;
        }
#endif
        qconf = &local_lcore_conf->pqs[i].txq;
        if (qconf->len <= 0)
            continue;
        netif_tx_burst(cid, pid);
        qconf->len = 0;
    }
}

static int timer_sched_interval_us;
static void lcore_job_timer_manage(void *args)
{
    static uint64_t tm_manager_time[DPVS_MAX_LCORE] = { 0 };
    uint64_t now = rte_get_timer_cycles();
    portid_t cid = rte_lcore_id();

    if (unlikely((now - tm_manager_time[cid]) * 1000000 / g_cycles_per_sec
            > timer_sched_interval_us)) {
        rte_timer_manage();
        tm_manager_time[cid] = now;
    }
}

#define NETIF_JOB_MAX   6

static struct dpvs_lcore_job_array netif_jobs[NETIF_JOB_MAX] = {
    [0] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "recv_fwd",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_recv_fwd,
    },

    [1] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "xmit",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_xmit,
    },

    [2] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "timer_manage",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_timer_manage,
    },

    [3] = {
        .role = LCORE_ROLE_ISOLRX_WORKER,
        .job.name = "isol_pkt_rcv",
        .job.type = LCORE_JOB_LOOP,
        .job.func = recv_on_isol_lcore,
    },

    [4] = {
        .role = LCORE_ROLE_MASTER,
        .job.name = "timer_manage",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_timer_manage,
    },
};

static void netif_lcore_init(void)
{
    int i, err;
    lcoreid_t cid;
    char buf1[1024], buf2[1024];

    timer_sched_interval_us = dpvs_timer_sched_interval_get();

    buf1[0] = buf2[0] = '\0';
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (rte_lcore_is_enabled(cid))
            snprintf(&buf1[strlen(buf1)], sizeof(buf1)-strlen(buf1), "%4d", cid);
        else
            snprintf(&buf2[strlen(buf2)], sizeof(buf2)-strlen(buf2), "%4d", cid);
    }
    RTE_LOG(INFO, NETIF, "LCORE STATUS\n\tenabled: %s\n\tdisabled: %s\n", buf1, buf2);

    /* init isolate rxqueue table */
    isol_rxq_init();

    /* check and set lcore config */
    config_lcores(&worker_list);
    if ((err = check_lcore_conf(rte_lcore_count(), lcore_conf)) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "%s: bad lcore configuration (error code: %d),"
                " exit ...\n", __func__, err);

    /* build port fast searching table */
    port_index_init();

    /* assign lcore roles */
    lcore_role_init();

    /* register lcore jobs*/
    if (g_kni_lcore_id == 0) {
        netif_jobs[5].role = LCORE_ROLE_MASTER;
        dpvs_lcore_job_init(&netif_jobs[5].job, "kni_master_proc",
                            LCORE_JOB_LOOP, kni_lcore_loop, 0);
    } else {
        netif_jobs[5].role = LCORE_ROLE_KNI_WORKER;
        dpvs_lcore_job_init(&netif_jobs[5].job, "kni_loop",
                            LCORE_JOB_LOOP, kni_lcore_loop, 0);
    }

    for (i = 0; i < NELEMS(netif_jobs); i++) {
        err = dpvs_lcore_job_register(&netif_jobs[i].job, netif_jobs[i].role);
        if (err < 0) {
            rte_exit(EXIT_FAILURE, "%s: fail to register lcore job '%s', exit ...\n",
                    __func__, netif_jobs[i].job.name);
            break;
        }
    }
}

static inline void netif_lcore_cleanup(void)
{
    int i;

    for (i = 0; i < NELEMS(netif_jobs); i++) {
        if (dpvs_lcore_job_unregister(&netif_jobs[i].job, netif_jobs[i].role) < 0)
            RTE_LOG(WARNING, NETIF, "%s: fail to unregister lcore job '%s'\n",
                    __func__, netif_jobs[i].job.name);
    }
}

static inline void free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
    unsigned i;

    if (pkts == NULL)
        return;

    for (i = 0; i < num; i++) {
        rte_pktmbuf_free(pkts[i]);
        pkts[i] = NULL;
    }
}

/********************************************** kni *************************************************/

void kni_ingress(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    if (!kni_dev_running(dev))
        goto freepkt;

    // TODO: Use `rte_ring_enqueue_bulk` for better performance.
    if (unlikely(rte_ring_enqueue(dev->kni.rx_ring, (void *)mbuf) != 0))
        goto freepkt;
    return;

freepkt:
#ifdef CONFIG_DPVS_NETIF_DEBUG
    RTE_LOG(INFO, NETIF, "%s: fail to enqueue packet to kni rx_ring\n", __func__);
#endif
    rte_pktmbuf_free(mbuf);
}

static void kni_egress(struct netif_port *port)
{
    unsigned i, npkts = 0;
#ifdef CONFIG_KNI_VIRTIO_USER
    static unsigned seq = 0;
    struct virtio_kni *vrtio_kni = port->kni.kni;
#endif
    struct rte_mbuf *kni_pkts_burst[NETIF_MAX_PKT_BURST];

    if (!kni_dev_running(port))
        return;

#ifdef CONFIG_KNI_VIRTIO_USER
    for (i = 0; i < vrtio_kni->queues && npkts < NETIF_MAX_PKT_BURST; i++) {
        npkts += rte_eth_rx_burst(vrtio_kni->dpdk_pid, seq % vrtio_kni->queues,
                &kni_pkts_burst[npkts], NETIF_MAX_PKT_BURST - npkts);
        seq++;
    }
#else
    npkts = rte_kni_rx_burst(port->kni.kni, kni_pkts_burst, NETIF_MAX_PKT_BURST);
#endif

    for (i = 0; i < npkts; i++) {
#ifdef CONFIG_KNI_VIRTIO_USER
        // DPVS is responsible for checksum calculation if tx-csum offload enabled on
        // the kernel tap interface. DPVS can either do the checksum itself, or further
        // offload the task to lower layer, i.e., the hardware nic. (Of course instead you
        // can disable the tx-csum offload feature with `ethtool -K dpdk0.kni tx off` so
        // that the task is done in tap driver software).
        kni_tx_csum(kni_pkts_burst[i]);
#endif
        if (unlikely(netif_xmit(kni_pkts_burst[i], port) != EDPVS_OK)) {
#ifdef CONFIG_DPVS_NETIF_DEBUG
            RTE_LOG(INFO, NETIF, "%s: fail to transmit kni packet", __func__);
#endif
        }
    }
}

static void kni_egress_process(void)
{
    struct netif_port *dev;
    portid_t id;
    int index;
    lcoreid_t cid = rte_lcore_id();
    struct netif_lcore_conf *local_lcore_conf = &lcore_conf[cid];
    for (index = 0; index < local_lcore_conf->nports; index++) {
        id = local_lcore_conf->pqs[index].id;
        dev = netif_port_get(id);
        if (!dev)
            continue;

#ifndef CONFIG_KNI_VIRTIO_USER
        kni_handle_request(dev);
#endif
        kni_egress(dev);
    }
}

/*
 * KNI rx rte_ring use mode as multi-producers and the single-consumer.
 */
static void kni_ingress_process(void)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    struct netif_port *dev;
    uint16_t i, pkt_total, pkt_sent;
    portid_t id, index;
    lcoreid_t cid = rte_lcore_id();
#ifdef CONFIG_KNI_VIRTIO_USER
    struct virtio_kni *virtio_kni;
    static unsigned seq = 0;
#endif
    struct netif_lcore_conf *local_lcore_conf = &lcore_conf[cid];
    for (index = 0; index < local_lcore_conf->nports; index++) {
        id = local_lcore_conf->pqs[index].id;
        dev = netif_port_get(id);
        if (!dev || !kni_dev_running(dev))
            continue;

        pkt_total = rte_ring_dequeue_burst(dev->kni.rx_ring, (void**)mbufs,
                                       NETIF_MAX_PKT_BURST, NULL);
        if (pkt_total == 0)
            continue;
        lcore_stats[cid].ipackets += pkt_total;
        for (i = 0; i < pkt_total; i++)
            lcore_stats[cid].ibytes += mbufs[i]->pkt_len;
#ifdef CONFIG_KNI_VIRTIO_USER
        virtio_kni = dev->kni.kni;
        pkt_sent = rte_eth_tx_burst(virtio_kni->dpdk_pid, seq % virtio_kni->queues,
                mbufs, pkt_total);
        seq++;
#else
        pkt_sent = rte_kni_tx_burst(dev->kni.kni, mbufs, pkt_total);
#endif

        if (unlikely(pkt_sent < pkt_total)) {
#ifdef CONFIG_DPVS_NETIF_DEBUG
            RTE_LOG(INFO, NETIF, "%s: sent %d packets to kni %s, loss %.2f%%\n",
                    __func__, pkt_total, dev->kni.name,
                    (pkt_total-pkt_sent)*100.0/pkt_total);
#endif
            free_mbufs(&(mbufs[pkt_sent]), pkt_total - pkt_sent);
            lcore_stats[cid].dropped += (pkt_total - pkt_sent);
        }
        pkt_total = 0;
    }
}

static inline void kni_ingress_flow_xmit_vlan_access(struct netif_port *dev,
            lcoreid_t cid, struct netif_queue_conf *qconf)
{
    unsigned pkt_sent;

    // pkt_sent = rte_kni_tx_burst(dev->kni.kni, qconf->mbufs, qconf->len);
    pkt_sent = rte_ring_enqueue_bulk(dev->kni.rx_ring, (void *const *)qconf->mbufs, qconf->len, NULL);

    if (unlikely(pkt_sent < qconf->len)) {
#ifdef CONFIG_DPVS_NETIF_DEBUG
        RTE_LOG(INFO, NETIF, "%s: enqueue %d packets to rx_ring of kni %s, loss %.2f%%\n",
                __func__, qconf->len, dev->kni.name,
                (qconf->len-pkt_sent)*100.0/qconf->len);
#endif
        free_mbufs(&(qconf->mbufs[pkt_sent]), qconf->len - pkt_sent);
        lcore_stats[cid].dropped += qconf->len - pkt_sent;
    }

    qconf->len = 0;
}

/*
 * Use separate core to convey kni traffic if KNI lcore worker is configued.
 */
void kni_lcore_loop(void *dummy)
{
    kni_ingress_process();
    kni_egress_process();
}

/********************************************* port *************************************************/
static inline int port_tab_hashkey(portid_t id)
{
    return id & NETIF_PORT_TABLE_MASK;
}

static unsigned int port_ntab_hashkey(const char *name, size_t len)
{
    int i;
    unsigned int hash=1315423911;
    for (i = 0; i < len; i++)
    {
        if (name[i] == '\0')
            break;
        hash^=((hash<<5)+name[i]+(hash>>2));
    }

    return (hash % NETIF_PORT_TABLE_BUCKETS);
}

static inline void port_tab_init(void)
{
    int i;
    for (i = 0; i < NETIF_PORT_TABLE_BUCKETS; i++) {
        rte_rwlock_init(&port_rwlock[i]);
        INIT_LIST_HEAD(&port_tab[i]);
    }
}

static inline void port_ntab_init(void)
{
    int i;
    for (i = 0; i < NETIF_PORT_TABLE_BUCKETS; i++) {
        rte_rwlock_init(&port_nrwlock[i]);
        INIT_LIST_HEAD(&port_ntab[i]);
    }
}

static inline portid_t netif_port_id_alloc(void)
{
    // The netif_port_id_alloc ensures the relation `g_nports == port_id_end` always stands,
    // which means all ids in range [0, port_id_end) are assgined to ports.
    portid_t pid;

    if (port_id_end > g_nports) {
        for (pid = port_id_end - 1; pid != 0; pid--) {
            if (netif_port_get(pid) == NULL)
                return pid;
        }
    }

    return port_id_end++;
}

portid_t netif_port_count(void)
{
    return port_id_end;
}

struct netif_port *netif_alloc(nsid_t nsid, portid_t id, size_t priv_size, const char *namefmt,
                               unsigned int nrxq, unsigned int ntxq,
                               void (*setup)(struct netif_port *))
{
    int ii;
    struct netif_port *dev;
    static const uint8_t mac_zero[6] = {0};

    size_t alloc_size;

    alloc_size = sizeof(struct netif_port);
    if (priv_size) {
        /* ensure 32-byte alignment of private area */
        alloc_size = __ALIGN_KERNEL(alloc_size, NETIF_ALIGN);
        alloc_size += priv_size;
    }

    dev = rte_zmalloc("netif", alloc_size, RTE_CACHE_LINE_SIZE);
    if (!dev) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return NULL;
    }
    dev->nsid = nsid;

    if (id != NETIF_PORT_ID_INVALID && !netif_port_get(id))
        dev->id = id;
    else
        dev->id = netif_port_id_alloc();

    if (strstr(namefmt, "%d"))
        snprintf(dev->name, sizeof(dev->name), namefmt, dev->id);
    else
        snprintf(dev->name, sizeof(dev->name), "%s", namefmt);

    rte_rwlock_init(&dev->dev_lock);
    dev->socket = SOCKET_ID_ANY;
    dev->hw_header_len = sizeof(struct rte_ether_hdr); /* default */

    if (setup)
        setup(dev);

    /* flag may set by setup() routine */
    dev->flag |= NETIF_PORT_FLAG_ENABLED;
    dev->nrxq = nrxq;
    dev->ntxq = ntxq;

    /* virtual dev has no NUMA-node */
    if (dev->socket == SOCKET_ID_ANY)
        dev->socket = rte_lcore_to_socket_id(g_master_lcore_id);
    dev->mbuf_pool = pktmbuf_pool[dev->socket];

    if (memcmp(&dev->addr, &mac_zero, sizeof(dev->addr)) == 0) {
        //TODO: use random lladdr ?
    }

    if (dev->mtu == 0)
        dev->mtu = ETH_DATA_LEN;

    netif_mc_init(dev);

    dev->in_ptr = rte_zmalloc(NULL, sizeof(struct inet_device), RTE_CACHE_LINE_SIZE);
    if (!dev->in_ptr) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        rte_free(dev);
        return NULL;
    }
    dev->in_ptr->dev = dev;
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        INIT_LIST_HEAD(&dev->in_ptr->ifa_list[ii]);
        INIT_LIST_HEAD(&dev->in_ptr->ifm_list[ii]);
    }

    if (tc_init_dev(dev) != EDPVS_OK) {
        RTE_LOG(ERR, NETIF, "%s: fail to init TC\n", __func__);
        rte_free(dev);
        return NULL;
    }

    return dev;
}

int netif_free(struct netif_port *dev)
{
    if (dev == NULL)
        return EDPVS_OK;
    tc_destroy_dev(dev);
    if (dev->in_ptr)
        rte_free(dev->in_ptr);
    rte_free(dev);
    return EDPVS_OK;
}

int netif_free_todo(struct netif_port *dev)
{
    // TODO:
    return EDPVS_OK;
}

static int dpdk_set_mc_list(struct netif_port *dev)
{
    struct rte_ether_addr addrs[NETIF_MAX_HWADDR];
    int err;
    size_t naddr = NELEMS(addrs);

    if (rte_eth_allmulticast_get(dev->id) == 1)
        return EDPVS_OK;

    err = __netif_mc_dump(dev, 0, addrs, &naddr);
    if (err != EDPVS_OK)
        return err;

    RTE_LOG(DEBUG, NETIF, "%s: configuring %lu multicast hw-addrs\n", dev->name, naddr);
    err = rte_eth_dev_set_mc_addr_list(dev->id, addrs, naddr);
    if (err) {
        RTE_LOG(WARNING, NETIF, "%s: rte_eth_dev_set_mc_addr_list failed -- %s,"
                "enable all multicast\n", dev->name, rte_strerror(-err));
        rte_eth_allmulticast_enable(dev->id);
        return EDPVS_OK;
    }

    return EDPVS_OK;
}

static int netif_op_get_xstats(struct netif_port *dev, netif_nic_xstats_get_t **pget)
{
    int i, nentries, err;
    struct rte_eth_xstat *xstats = NULL;
    struct rte_eth_xstat_name *xstats_names = NULL;
    netif_nic_xstats_get_t *get = NULL;

    nentries = rte_eth_xstats_get(dev->id, NULL, 0);
    if (nentries < 0)
        return EDPVS_DPDKAPIFAIL;

    get = rte_calloc("xstats_get", 1, sizeof(*get) + nentries * sizeof(struct netif_nic_xstats_entry), 0);
    if (unlikely(!get))
        return EDPVS_NOMEM;
    xstats = rte_calloc("xstats", 1, nentries * sizeof(struct rte_eth_xstat), 0);
    if (unlikely(!xstats)) {
        err = EDPVS_NOMEM;
        goto errout;
    }
    xstats_names = rte_calloc("xstats_names", 1, nentries * sizeof(struct rte_eth_xstat_name), 0);
    if (unlikely(!xstats_names)) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    err = rte_eth_xstats_get(dev->id, xstats, nentries);
    if (err < 0 || err != nentries)
        goto errout;
    err = rte_eth_xstats_get_names(dev->id, xstats_names, nentries);
    if (err < 0 || err != nentries)
        goto errout;
    get->pid = dev->id;
    get->nentries = nentries;
    for (i = 0; i < nentries; i++) {
        get->entries[i].id = xstats[i].id;
        get->entries[i].val = xstats[i].value;
        rte_memcpy(get->entries[i].name, xstats_names[i].name, sizeof(get->entries[i].name)-1);
    }

    *pget = get;
    rte_free(xstats);
    rte_free(xstats_names);
    return EDPVS_OK;
errout:
    if (xstats)
        rte_free(xstats);
    if (xstats_names)
        rte_free(xstats_names);
    if (get)
        rte_free(get);
    if (err == EDPVS_OK)
        err = EDPVS_RESOURCE;
    *pget = NULL;
    return err;
}

static struct netif_ops dpdk_netif_ops = {
    .op_set_mc_list      = dpdk_set_mc_list,
    .op_get_xstats       = netif_op_get_xstats,
};


static inline void setup_dev_of_flags(struct netif_port *port)
{
    port->flag |= NETIF_PORT_FLAG_ENABLED;

    /* tx offload conf and flags */
    if (port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD;

    if (port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;

    if (port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;

    // Device supports optimization for fast release of mbufs.
    // The feature is configurable via dpvs.conf.
    // When set application must guarantee that per-queue all mbufs comes from
    // the same mempool and has refcnt = 1.
    // https://doc.dpdk.org/api/rte__ethdev_8h.html#a43f198c6b59d965130d56fd8f40ceac1
    if (!(port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE))
        port->flag &= ~NETIF_PORT_FLAG_TX_MBUF_FAST_FREE;

    /* FIXME: may be a bug in dev_info get for virtio device,
     *        set the txq_of_flags manually for this type device */
    if (strncmp(port->dev_info.driver_name, "net_virtio", strlen("net_virtio")) == 0) {
        // port->flag |= NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD;
        port->flag &= ~NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;
        port->flag &= ~NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;
    }

    /*
     * we may have multiple vlan dev on one rte_ethdev,
     * and mbuf->vlan_tci is RX only!
     * while there's only one PVID (DEV_TX_OFFLOAD_VLAN_INSERT),
     * to make things easier, do not support TX VLAN instert offload.
     * or we have to check if VID is PVID (than to tx offload it).
     */
#if 0
    if (dev_info->tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT) {
        port->flag |= NETIF_PORT_FLAG_TX_VLAN_INSERT_OFFLOAD;
        port->dev_conf.txmode.hw_vlan_insert_pvid = 1;
        rte_eth_dev_set_vlan_pvid();
    }
#endif

    /* rx offload conf and flags */
    if (port->dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
        port->flag |= NETIF_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD;
    if (port->dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
        port->flag |= NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD;

    /* enable lldp on physical port */
    if (is_physical_port(port->id))
        port->flag |= NETIF_PORT_FLAG_LLDP;
}

struct netif_port* netif_port_get(portid_t id)
{
    int hash = port_tab_hashkey(id);
    struct netif_port *port;
    assert(id <= NETIF_MAX_PORTS);

    rte_rwlock_read_lock(&port_rwlock[hash]);
    list_for_each_entry(port, &port_tab[hash], list) {
        if (port->id == id) {
            rte_rwlock_read_unlock(&port_rwlock[hash]);
            return port;
        }
    }
    rte_rwlock_read_unlock(&port_rwlock[hash]);

    return NULL;
}

struct netif_port* netif_port_get_by_name(const char *name)
{
    int nhash;
    struct netif_port *port;

    if (!name || strlen(name) <= 0)
        return NULL;

    nhash = port_ntab_hashkey(name, strlen(name));
    rte_rwlock_read_lock(&port_nrwlock[nhash]);
    list_for_each_entry(port, &port_ntab[nhash], nlist) {
        if (!strcmp(port->name, name)) {
            rte_rwlock_read_unlock(&port_nrwlock[nhash]);
            return port;
        }
    }
    rte_rwlock_read_unlock(&port_nrwlock[nhash]);

    return NULL;
}

int netif_get_link(struct netif_port *dev, struct rte_eth_link *link)
{
    assert(dev && dev->netif_ops && link);

    if (dev->netif_ops->op_get_link)
        return dev->netif_ops->op_get_link(dev, link);

    rte_eth_link_get_nowait((uint8_t)dev->id, link);
    return EDPVS_OK;
}

int netif_get_promisc(struct netif_port *dev, bool *promisc)
{
    assert(dev && dev->netif_ops && promisc);

    if (dev->netif_ops->op_get_promisc)
        return dev->netif_ops->op_get_promisc(dev, promisc);

    *promisc = rte_eth_promiscuous_get(dev->id) ? true : false;
    return EDPVS_OK;
}

int netif_get_allmulticast(struct netif_port *dev, bool *allmulticast)
{
    assert(dev && dev->netif_ops && allmulticast);

    if (dev->netif_ops->op_get_allmulticast)
        return dev->netif_ops->op_get_allmulticast(dev, allmulticast);

    *allmulticast = rte_eth_allmulticast_get(dev->id) ? true : false;
    return EDPVS_OK;
}

int netif_get_stats(struct netif_port *dev, struct rte_eth_stats *stats)
{
    int err;
    assert(dev && dev->netif_ops && stats);

    if (dev->netif_ops->op_get_stats)
        return dev->netif_ops->op_get_stats(dev, stats);

    err = rte_eth_stats_get((uint8_t)dev->id, stats);
    if (err)
        return EDPVS_DPDKAPIFAIL;

    return EDPVS_OK;
}

int netif_get_xstats(struct netif_port *dev, netif_nic_xstats_get_t **xstats)
{
    assert (dev && dev->netif_ops && xstats);

    if (dev->netif_ops->op_get_xstats)
        return dev->netif_ops->op_get_xstats(dev, xstats);

    return EDPVS_NOTSUPP;
}

int netif_port_conf_get(struct netif_port *port, struct rte_eth_conf *eth_conf)
{

    if (unlikely(NULL == port))
        return EDPVS_INVAL;

    rte_rwlock_read_lock(&port->dev_lock);
    *eth_conf = port->dev_conf;
    rte_rwlock_read_unlock(&port->dev_lock);

    return EDPVS_OK;
}

int netif_port_conf_set(struct netif_port *port, const struct rte_eth_conf *conf)
{
    if (unlikely(NULL == port || NULL == conf))
        return EDPVS_INVAL;

    rte_rwlock_write_lock(&port->dev_lock);
    memcpy(&port->dev_conf, conf, sizeof(struct rte_eth_conf));
    rte_rwlock_write_unlock(&port->dev_lock);

    return EDPVS_OK;
};

static inline void port_mtu_set(struct netif_port *port)
{
    uint16_t mtu;

    rte_eth_dev_get_mtu(port->id, &mtu);

    port->mtu = mtu;

    rte_eth_dev_set_mtu((uint8_t)port->id,port->mtu);

}

/* check and adapt device offloading/rss features */
static void adapt_device_conf(portid_t port_id, uint64_t *rss_hf,
        uint64_t *rx_offload, uint64_t *tx_offload)
{
    struct rte_eth_dev_info dev_info;

    rte_eth_dev_info_get(port_id, &dev_info);

    if ((dev_info.flow_type_rss_offloads | *rss_hf) !=
        dev_info.flow_type_rss_offloads) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid rss_hf: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *rss_hf, dev_info.flow_type_rss_offloads);
        /* mask the unsupported rss_hf */
        *rss_hf &= dev_info.flow_type_rss_offloads;
    }

    if ((dev_info.rx_offload_capa | *rx_offload) != dev_info.rx_offload_capa) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid rx_offload: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *rx_offload, dev_info.rx_offload_capa);
        /* mask the unsupported rx_offload */
        *rx_offload &= dev_info.rx_offload_capa;
    }

    if ((dev_info.tx_offload_capa | *tx_offload) != dev_info.tx_offload_capa) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid tx_offload: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *tx_offload, dev_info.tx_offload_capa);
        /* mask the unsupported tx_offload */
        *tx_offload &= dev_info.tx_offload_capa;
    }
}

/* fill in rx/tx queue configurations, including queue number, decriptor number */
static void fill_port_config(struct netif_port *port, char *promisc_on, char *allmulticast)
{
    assert(port);

    port->nrxq = g_slave_lcore_num;
    port->ntxq = g_slave_lcore_num;


    /* using default configurations */
    port->rxq_desc_nb = NETIF_NB_RX_DESC_DEF;
    port->txq_desc_nb = NETIF_NB_TX_DESC_DEF;
    port->mtu = NETIF_DEFAULT_ETH_MTU;

    *promisc_on = 1;
    *allmulticast = 1;
}

/*
 * Note: Invoke the function after port is allocated and lcores are configured.
 */
int netif_port_start(struct netif_port *port)
{
    int ii, ret;
    queueid_t qid;
    char promisc_on, allmulticast;
    char buf[512];
    struct rte_eth_txconf txconf;
    struct rte_eth_link link;
    const int wait_link_up_msecs = 30000; //30s
    int buflen = sizeof(buf);

    if (unlikely(NULL == port))
        return EDPVS_INVAL;

    fill_port_config(port, &promisc_on, &allmulticast);
    if (!port->nrxq && !port->ntxq) {
        RTE_LOG(WARNING, NETIF, "%s: no queues to setup for %s\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    if (port->nrxq > port->dev_info.max_rx_queues ||
            port->ntxq > port->dev_info.max_tx_queues) {
        RTE_LOG(WARNING, NETIF,  "%s: %s supports %d rx-queues and %d tx-queues at max, "
                "but %d rx-queues and %d tx-queues are configured.\n", __func__,
                port->name, port->dev_info.max_rx_queues,
                port->dev_info.max_tx_queues, port->nrxq, port->ntxq);
        return EDPVS_RESOURCE;
    }


    if (port->flag & NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD)
        port->dev_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
    if (port->flag & NETIF_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD)
        port->dev_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;

    if (port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    if (port->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    if (port->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    if (port->flag & NETIF_PORT_FLAG_TX_MBUF_FAST_FREE)
        port->dev_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    adapt_device_conf(port->id, &port->dev_conf.rx_adv_conf.rss_conf.rss_hf,
            &port->dev_conf.rxmode.offloads, &port->dev_conf.txmode.offloads);

    ret = rte_eth_dev_configure(port->id, port->nrxq, port->ntxq, &port->dev_conf);
    if (ret < 0 ) {
        RTE_LOG(ERR, NETIF, "%s: fail to config %s\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }
    
    // device configure
    if ((ret = rte_eth_dev_set_mtu(port->id,port->mtu)) != EDPVS_OK)
        return ret;

    // setup rx queues
    if (port->nrxq > 0) {
        for (qid = 0; qid < port->nrxq; qid++) {
            ret = rte_eth_rx_queue_setup(port->id, qid, port->rxq_desc_nb,
                    port->socket, NULL, pktmbuf_pool[port->socket]);
            if (ret < 0) {
                RTE_LOG(ERR, NETIF, "%s: fail to config %s:rx-queue-%d\n",
                        __func__, port->name, qid);
                return EDPVS_DPDKAPIFAIL;
            }
        }
    }

    // setup tx queues
    if (port->ntxq > 0) {
        for (qid = 0; qid < port->ntxq; qid++) {
            memcpy(&txconf, &port->dev_info.default_txconf, sizeof(struct rte_eth_txconf));
            txconf.offloads = port->dev_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(port->id, qid, port->txq_desc_nb,
                    port->socket, &txconf);
            if (ret < 0) {
                RTE_LOG(ERR, NETIF, "%s: fail to config %s:tx-queue-%d\n",
                        __func__, port->name, qid);
                return EDPVS_DPDKAPIFAIL;
            }
        }
    }

    netif_print_port_conf(&port->dev_conf, buf, &buflen);
    RTE_LOG(INFO, NETIF, "device %s configuration:\n%s\n", port->name, buf);

    // start the device
    ret = rte_eth_dev_start(port->id);
    if (ret < 0) {
        RTE_LOG(ERR, NETIF, "%s: fail to start %s\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    // wait the device link up
    RTE_LOG(INFO, NETIF, "Waiting for %s link up, be patient ...\n", port->name);
    for (ii = 0; ii < wait_link_up_msecs; ii++) {
        rte_eth_link_get_nowait(port->id, &link);
        if (link.link_status) {
            RTE_LOG(INFO, NETIF, ">> %s: link up - speed %u Mbps - %s\n",
                    port->name, (unsigned)link.link_speed,
                    (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
                    "full-duplex" : "half-duplex");
            break;
        }
        rte_delay_ms(1);
    }
    if (!link.link_status) {
        RTE_LOG(ERR, NETIF, "%s: fail to bring up %s\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    port->flag |= NETIF_PORT_FLAG_RUNNING;

    // enable promicuous mode if configured
    if (promisc_on) {
        RTE_LOG(INFO, NETIF, "promiscous mode enabled for device %s\n", port->name);
        rte_eth_promiscuous_enable(port->id);
    }

    // enable allmulticast mode if configured
    if (allmulticast) {
        RTE_LOG(INFO, NETIF, "allmulticast enabled for device %s\n", port->name);
        rte_eth_allmulticast_enable(port->id);
    }

     /* update mac addr to netif_port and netif_kni after start */
    if (port->netif_ops->op_update_addr)
        port->netif_ops->op_update_addr(port);



#if 0
    /* disable kni tx-csum offload feature
     *
     * Why we redo this while it's done in virtio_kni_start? We found in some systems,
     * say linux 5.10.134, the tx-csum feature of virtio kni device gets re-enabled
     * some moments later after virito_kni_start.
     * */
    if (kni_dev_exist(port))
        disable_kni_tx_csum_offload(port->kni.name);
#endif

    return EDPVS_OK;
}

int netif_port_stop(struct netif_port *port)
{
    int ret;

    if (unlikely(NULL == port))
        return EDPVS_INVAL;

    rte_eth_dev_stop(port->id);
    ret = rte_eth_dev_set_link_down(port->id);
    if (ret < 0 && ret != -ENOTSUP) {
        RTE_LOG(WARNING, NETIF, "%s: fail to set %s link down\n", __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    port->flag |= NETIF_PORT_FLAG_STOPPED;
    return EDPVS_OK;
}

int netif_port_register(struct netif_port *port)
{
    struct netif_port *cur;
    int hash, nhash;
    int err;

    if (unlikely(NULL == port))
        return EDPVS_INVAL;

    hash = port_tab_hashkey(port->id);
    rte_rwlock_write_lock(&port_rwlock[hash]);
    list_for_each_entry(cur, &port_tab[hash], list) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            rte_rwlock_write_unlock(&port_rwlock[hash]);
            return EDPVS_EXIST;
        }
    }
    list_add_tail(&port->list, &port_tab[hash]);
    rte_rwlock_write_unlock(&port_rwlock[hash]);

    nhash = port_ntab_hashkey(port->name, sizeof(port->name));
    rte_rwlock_write_lock(&port_nrwlock[nhash]);
    list_for_each_entry(cur, &port_ntab[nhash], nlist) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            rte_rwlock_write_unlock(&port_nrwlock[nhash]);
            return EDPVS_EXIST;
        }
    }
    list_add_tail(&port->nlist, &port_ntab[nhash]);
    rte_rwlock_write_unlock(&port_nrwlock[nhash]);

    g_nports++;

    if (port->netif_ops->op_init) {
        err = port->netif_ops->op_init(port);
        if (err != EDPVS_OK) {
            netif_port_unregister(port);
            return err;
        }
    }

    return EDPVS_OK;
}

int netif_port_unregister(struct netif_port *port)
{
    struct netif_port *cur, *next;
    int ret1, ret2, hash, nhash;
    if (unlikely(NULL == port))
        return EDPVS_INVAL;
    ret1 = ret2 = EDPVS_NOTEXIST;

    hash = port_tab_hashkey(port->id);
    rte_rwlock_write_lock(&port_rwlock[hash]);
    list_for_each_entry_safe(cur, next, &port_tab[hash], list) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            list_del_init(&cur->list);
            ret1 = EDPVS_OK;
            break;
        }
    }
    rte_rwlock_write_unlock(&port_rwlock[hash]);

    nhash = port_ntab_hashkey(port->name, sizeof(port->name));
    rte_rwlock_write_lock(&port_nrwlock[nhash]);
    list_for_each_entry_safe(cur, next, &port_ntab[nhash], nlist) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            list_del_init(&cur->nlist);
            ret2 = EDPVS_OK;
            break;
        }
    }
    rte_rwlock_write_unlock(&port_nrwlock[nhash]);

    if (ret1 != EDPVS_OK || ret2 != EDPVS_OK)
        return EDPVS_NOTEXIST;

    g_nports--;
    return EDPVS_OK;
}

static int netif_seq(void) {
    static int i = 0;
    return i++;
}

static void netif_flush_lcore(nsid_t nsid)
{

    portid_t pid;
    int cid = rte_lcore_id();
    int first_index = 0, second_index = 0;

    struct netif_lcore_conf *local_lcore_conf = &lcore_conf[cid];

    if (local_lcore_conf->nports <= 0) {
        return;
    } 
    for (second_index = 0; second_index < local_lcore_conf->nports; second_index++) {
        if (local_lcore_conf->pqs[second_index].nsid == nsid) {
            continue;
        } else {
            pid = local_lcore_conf->pqs[second_index].id;
            port2index[cid][pid] = first_index;
            rte_memcpy(&local_lcore_conf->pqs[first_index++],
                        &local_lcore_conf->pqs[second_index],
                            sizeof(struct netif_lcore_conf));
        }
    }
    local_lcore_conf->nports = first_index;
}

void flush_arp_ring_lcore(nsid_t nsid, lcoreid_t cid)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;
    int i;
    do {
        nb_rb = rte_ring_dequeue_burst(arp_ring[nsid][cid], (void**)mbufs, NETIF_MAX_PKT_BURST, NULL);
        for (i = 0; i < nb_rb; i++) {
            rte_pktmbuf_free(mbufs[i]);
        }
    } while (nb_rb > 0);
}

int netif_port_flush(nsid_t nsid) {
    int cid = rte_lcore_id();
    struct dpvs_msg *msg;
    int i, ret;
    portid_t pid;
    struct netif_port *port;
    struct netif_lcore_conf *local_lcore_conf = &lcore_conf[cid];
    // 删除lcore/kni中的lcore_conf，其他lcore就不会去操作对应的port，如此确保后续删除port操作是安全的

    // flush netif
    msg = msg_make(MSG_TYPE_NETIF_FLUSH, netif_seq(), DPVS_MSG_MULTICAST, cid, sizeof(nsid_t), &nsid);
    if (msg == NULL) {
        return EDPVS_NOMEM;
    }
    // 此处为同步操作，确保清理动作完成
    ret = multicast_msg_send(msg, DPVS_MSG_F_WITH_KNI, NULL);
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, NETIF, "[%s] fail to send multicast message, error code = %d\n", __func__, ret);
        return ret;
    }

    // flush neigh
    ret = neigh_flush(nsid);
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, NETIF, "[%s] fail to flush conn, error code = %d\n", __func__, ret);
        return ret;
    }

    // 删除port
    for (i = 0; i < local_lcore_conf->nports; i++) {
        if (nsid != local_lcore_conf->pqs[i].nsid)
            continue;
        pid = local_lcore_conf->pqs[i].id;
        port = netif_port_get(pid);
        if (!port) {
            RTE_LOG(WARNING, NETIF, "%s: fail to get port by id %d\n", __func__, pid);
            continue;
        }
        ret = remove_virtio_user(port);
        if (ret != EDPVS_OK) {
            RTE_LOG(WARNING, NETIF, "%s: fail to remove port %s\n", __func__, port->name);
            return ret;
        }
    }
    // 清理master lcore的lcore_conf
    netif_flush_lcore(nsid);


    return EDPVS_OK;
}

int netif_flush_inet_addr_all(nsid_t nsid)
{
    lcoreid_t cid = rte_lcore_id();
    struct netif_lcore_conf *local_lcore_conf = &lcore_conf[cid];
    int i, ret;
    portid_t pid;
    struct netif_port *port;
    for (i = 0; i < local_lcore_conf->nports; i++) {
        if (nsid != local_lcore_conf->pqs[i].nsid)
            continue;
        pid = local_lcore_conf->pqs[i].id;
        port = netif_port_get(pid);
        if (!port) {
            RTE_LOG(WARNING, NETIF, "%s: fail to get port by id %d\n", __func__, pid);
            continue;
        }
        ret = inet_addr_flush(0, port);
        if (ret != EDPVS_OK) {
            RTE_LOG(ERR, NETIF, "%s: fail to flush port %s inet addr\n", __func__, port->name);
            return ret;
        }
    }
    return EDPVS_OK;
}

static struct rte_eth_conf default_port_conf = {
    .rxmode = {
        .mq_mode        = RTE_ETH_MQ_RX_NONE,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

int netif_print_port_conf(const struct rte_eth_conf *port_conf, char *buf, int *len)
{
    char tbuf1[256], tbuf2[128];
    if (unlikely(NULL == buf) || 0 == len)
        return EDPVS_INVAL;
    if (port_conf == NULL)
        port_conf = &default_port_conf;

    memset(buf, 0, *len);
    if (port_conf->rxmode.mq_mode == RTE_ETH_MQ_RX_RSS) {
        memset(tbuf2, 0, sizeof(tbuf2));
        if (port_conf->rx_adv_conf.rss_conf.rss_hf) {
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_IP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "RTE_ETH_RSS_IP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_TCP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "RTE_ETH_RSS_TCP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_UDP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "RTE_ETH_RSS_UDP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_SCTP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "RTE_ETH_RSS_SCTP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_L2_PAYLOAD)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "RTE_ETH_RSS_L2_PAYLOAD ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_PORT)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "RTE_ETH_RSS_PORT ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_TUNNEL)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "RTE_ETH_RSS_TUNNEL ");
        } else {
            snprintf(tbuf2, sizeof(tbuf2), "Inhibited");
        }

        memset(tbuf1, 0, sizeof(tbuf1));
        snprintf(tbuf1, sizeof(tbuf1), "RSS: %s\n", tbuf2);
        if (*len - strlen(buf) - 1 < strlen(tbuf1)) {
            RTE_LOG(WARNING, NETIF, "[%s] no enough buf\n", __func__);
            return EDPVS_INVAL;
        }
        strncat(buf, tbuf1, *len - strlen(buf) - 1);
    }

    *len = strlen(buf);
    return EDPVS_OK;
}

void dpdk_port_setup(struct netif_port *dev)
{
    dev->type      = PORT_TYPE_GENERAL;
    dev->netif_ops = &dpdk_netif_ops;
    dev->socket    = rte_eth_dev_socket_id(dev->id);
    dev->dev_conf  = default_port_conf;

    rte_eth_macaddr_get(dev->id, &dev->addr);
    rte_eth_dev_get_mtu(dev->id, &dev->mtu);
    rte_eth_dev_info_get(dev->id, &dev->dev_info);
    setup_dev_of_flags(dev);
}

/* Allocate and register all DPDK ports available */
static void netif_port_init(void)
{

    port_tab_init();
    port_ntab_init();

    // portid_t pid;
    // struct netif_port *port;
    // char *kni_name;
    // char ifname[IFNAMSIZ];

    // for (pid = 0; pid < nports; pid++) {
    //     if (port_name_alloc(pid, ifname, sizeof(ifname)) != EDPVS_OK)
    //         rte_exit(EXIT_FAILURE, "Port name allocation failed, exiting...\n");

    //     /* queue number will be filled on device start */
    //     port = NULL;
    //     if (is_physical_port(pid))
    //         port = netif_alloc(pid, 0, ifname, 0, 0, dpdk_port_setup);
    //     if (!port)
    //         rte_exit(EXIT_FAILURE, "Port allocation failed, exiting...\n");
    //     port->nsid = nsid_get(pid);
    //     if (netif_port_register(port) < 0)
    //         rte_exit(EXIT_FAILURE, "Port registration failed, exiting...\n");
    // }

    // /* auto generate KNI device for all build-in
    //  * phy ports and bonding master ports, but not bonding slaves */
    // for (pid = 0; pid < nports; pid++) {
    //     port = netif_port_get(pid);
    //     assert(port);

    //     kni_name = find_conf_kni_name(pid);

    //     /* it's ok if no KNI name (kni_name is NULL) */
    //     if (kni_add_dev(port, kni_name) < 0)
    //         rte_exit(EXIT_FAILURE, "add KNI port fail, exiting...\n");
    // }
}

int netif_init(void)
{
    netif_pktmbuf_pool_init();
    netif_arp_ring_init();
    netif_pkt_type_tab_init();
    netif_port_init();
    netif_lcore_init();

    g_master_lcore_id = rte_get_main_lcore();
    netif_get_slave_lcores(&g_slave_lcore_num, &g_slave_lcore_mask);
    netif_get_isol_rx_lcores(&g_isol_rx_lcore_num, &g_isol_rx_lcore_mask);

    return EDPVS_OK;
}

int netif_term(void)
{
    netif_lcore_cleanup();
    netif_cfgfile_term();
    return EDPVS_OK;
}


/************************************ Ctrl Plane ***************************************/

static int get_lcore_mask(void **out, size_t *out_len)
{
    assert(out && out_len);

    netif_lcore_mask_get_t *get;

    get = rte_zmalloc(NULL, sizeof(netif_lcore_mask_get_t),
            RTE_CACHE_LINE_SIZE);
    if (unlikely (NULL == get))
        return EDPVS_NOMEM;

    get->master_lcore_id = g_master_lcore_id;
    get->kni_lcore_id = g_kni_lcore_id;
    get->slave_lcore_num = g_slave_lcore_num;
    get->slave_lcore_mask = g_slave_lcore_mask;
    get->isol_rx_lcore_num = g_isol_rx_lcore_num;
    get->isol_rx_lcore_mask = g_isol_rx_lcore_mask;

    *out = get;
    *out_len = sizeof(netif_lcore_mask_get_t);

    return EDPVS_OK;
}

static int get_lcore_basic(lcoreid_t cid, void **out, size_t *out_len)
{
    assert(out && out_len);

    netif_lcore_basic_get_t *get;
    int err, len;
    char buf[NETIF_CTRL_BUFFER_LEN];

    len = NETIF_CTRL_BUFFER_LEN;
    if (is_isol_rxq_lcore(cid))
        err = netif_print_isol_lcore_conf(cid, buf, &len, false);
    else
        err = netif_print_lcore_queue_conf(cid, buf, &len, false);

    if (unlikely(!(EDPVS_OK == err)))
        return err;
    assert(len < NETIF_CTRL_BUFFER_LEN);

    get = rte_zmalloc(NULL, sizeof(netif_lcore_basic_get_t) + len,
            RTE_CACHE_LINE_SIZE);
    if (unlikely(NULL == get))
        return EDPVS_NOMEM;

    get->lcore_id = cid;
    get->socket_id = rte_lcore_to_socket_id(cid);
    get->queue_data_len = len;
    memcpy(&get->queue_data[0], buf, len);

    *out = get;
    *out_len = sizeof(netif_lcore_basic_get_t) + len;

    return EDPVS_OK;
}

static int lcore_stats_msg_cb(struct dpvs_msg *msg)
{
    void *reply_data;

    if (unlikely(!msg || msg->type != MSG_TYPE_NETIF_LCORE_STATS ||
                msg->mode != DPVS_MSG_UNICAST))
        return EDPVS_INVAL;

    reply_data = msg_reply_alloc(sizeof(struct netif_lcore_stats));
    if (unlikely(!reply_data))
        return EDPVS_NOMEM;

    netif_copy_lcore_stats(reply_data);

    msg->reply.len = sizeof(struct netif_lcore_stats);
    msg->reply.data = reply_data;

    return EDPVS_OK;
}

static inline int lcore_stats_msg_init(void)
{
    int ii, err;
    struct dpvs_msg_type lcore_stats_msg_type = {
        .type = MSG_TYPE_NETIF_LCORE_STATS,
        .mode = DPVS_MSG_UNICAST,
        .prio = MSG_PRIO_LOW,
        .unicast_msg_cb = lcore_stats_msg_cb,
        .multicast_msg_cb = NULL,
    };

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if ((ii == g_master_lcore_id) || (g_slave_lcore_mask & (1L << ii))) {
            lcore_stats_msg_type.cid = ii;
            err = msg_type_register(&lcore_stats_msg_type);
            if (EDPVS_OK != err) {
                RTE_LOG(WARNING, NETIF, "[%s] fail to register NETIF_LCORE_STATS msg-type "
                        "on lcore%d: %s\n", __func__, ii, dpvs_strerror(err));
                return err;
            }
        }
    }

    return EDPVS_OK;
}

static queueid_t get_lcore_queue_id(int cid) {
    queueid_t qid = 0;
    int i;
    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if (!(g_slave_lcore_mask & (1UL << i)))
            continue;
        if (cid == i) {
            break;
        } else {
            qid++;
        }
    }
    return qid;
}



static int netif_flush_msg_cb(struct dpvs_msg *msg) {
    nsid_t nsid = *(nsid_t *)msg->data;
    netif_flush_lcore(nsid);
    return EDPVS_OK;
}

static void netif_add_lcore(struct netif_port *port)
{
    int cid = rte_lcore_id();
    struct netif_lcore_conf *local_lcore_conf = &lcore_conf[cid];
    int port_index = local_lcore_conf->nports;
    struct netif_port_conf *new_port = &(local_lcore_conf->pqs[port_index]);

    RTE_LOG(INFO, NETIF, "[%02d] %s: add netif %s\n", cid, __func__, port->name); 

    new_port->id = port->id;
    new_port->nsid = port->nsid;
    new_port->rxq.len = 0;
    new_port->rxq.isol_rxq = NULL;
    new_port->rxq.id = get_lcore_queue_id(cid);

    port2index[cid][port->id] = port_index;

    local_lcore_conf->nports++;
}

int netif_add(struct netif_port *port) {
    int ret;
    struct dpvs_msg *msg;

    netif_add_lcore(port);
    msg = msg_make(MSG_TYPE_NETIF_ADD, netif_seq(), DPVS_MSG_MULTICAST,
        rte_lcore_id(), sizeof(struct netif_port*), &port);
    if (!msg) {
        return EDPVS_NOMEM;
    }

    ret = multicast_msg_send(msg, DPVS_MSG_F_ASYNC|DPVS_MSG_F_WITH_KNI, NULL);
    if (ret != EDPVS_OK) {
        RTE_LOG(INFO, NETIF, "[%s] fail to send message, error code = %d\n", __func__, ret);
    }
    msg_destroy(&msg);
    return ret;
}

static int netif_add_msg_cb(struct dpvs_msg *msg)
{
    struct netif_port *port = *((struct netif_port**) msg->data);
    netif_add_lcore(port);
    return EDPVS_OK;
}

static inline int netif_msg_init(void)
{
    int ii, err;
    struct dpvs_msg_type netif_msg_type[2] = {
        {
            .type = MSG_TYPE_NETIF_ADD,
            .mode = DPVS_MSG_MULTICAST,
            .prio = MSG_PRIO_NORM,
            .unicast_msg_cb = netif_add_msg_cb,
            .multicast_msg_cb = NULL,
        },
        {
            .type = MSG_TYPE_NETIF_FLUSH,
            .mode = DPVS_MSG_MULTICAST,
            .prio = MSG_PRIO_NORM,
            .unicast_msg_cb = netif_flush_msg_cb,
            .multicast_msg_cb = NULL,
        },

    };

    netif_msg_type[0].cid = g_kni_lcore_id;
    err = msg_type_register(&netif_msg_type[0]);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, NETIF, "[%s] fail to register msg-type: %s\n", __func__, dpvs_strerror(err));
        return err;
    }
    err = msg_type_mc_register(&netif_msg_type[0]);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, NETIF, "[%s] fail to register msg-type: %s\n", __func__, dpvs_strerror(err));
        return err;
    }

    netif_msg_type[1].cid = g_kni_lcore_id;
    err = msg_type_register(&netif_msg_type[1]);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, NETIF, "[%s] fail to register msg-type: %s\n", __func__, dpvs_strerror(err));
        return err;
    }
    err = msg_type_mc_register(&netif_msg_type[1]);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, NETIF, "[%s] fail to register msg-type: %s\n", __func__, dpvs_strerror(err));
        return err;
    }

    return EDPVS_OK;
}

static inline int netif_msg_term(void)
{
    int ii, err;
    struct dpvs_msg_type netif_msg_type[2] = {
        {
            .type = MSG_TYPE_NETIF_ADD,
            .mode = DPVS_MSG_MULTICAST,
            .prio = MSG_PRIO_NORM,
            .unicast_msg_cb = netif_add_msg_cb,
            .multicast_msg_cb = NULL,
        },
        {
            .type = MSG_TYPE_NETIF_FLUSH,
            .mode = DPVS_MSG_MULTICAST,
            .prio = MSG_PRIO_NORM,
            .unicast_msg_cb = netif_flush_msg_cb,
            .multicast_msg_cb = NULL,
        },

    };

    netif_msg_type[0].cid = g_kni_lcore_id;
    err = msg_type_unregister(&netif_msg_type[0]);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, NETIF, "[%s] fail to unregister msg-type: %s\n", __func__, dpvs_strerror(err));
        return err;
    }
    err = msg_type_mc_unregister(&netif_msg_type[0]);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, NETIF, "[%s] fail to unregister msg-type: %s\n", __func__, dpvs_strerror(err));
        return err;
    }

    netif_msg_type[1].cid = g_kni_lcore_id;
    err = msg_type_unregister(&netif_msg_type[1]);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, NETIF, "[%s] fail to unregister msg-type: %s\n", __func__, dpvs_strerror(err));
        return err;
    }
    err = msg_type_mc_unregister(&netif_msg_type[1]);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, NETIF, "[%s] fail to unregister msg-type: %s\n", __func__, dpvs_strerror(err));
        return err;
    }

    return EDPVS_OK;
}

static inline int lcore_stats_msg_term(void)
{
    int ii, err;
    struct dpvs_msg_type lcore_stats_msg_type = {
        .type = MSG_TYPE_NETIF_LCORE_STATS,
        .mode = DPVS_MSG_UNICAST,
        .prio = MSG_PRIO_LOW,
        .unicast_msg_cb = lcore_stats_msg_cb,
        .multicast_msg_cb = NULL,
    };

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if ((ii == g_master_lcore_id) || (g_slave_lcore_mask & (1L << ii))) {
            lcore_stats_msg_type.cid = ii;
            err = msg_type_unregister(&lcore_stats_msg_type);
            if (EDPVS_OK != err) {
                RTE_LOG(WARNING, NETIF, "[%s] fail to unregister NETIF_LCORE_STATS msg-type "
                        "on lcore%d: %s\n", __func__, ii, dpvs_strerror(err));
                return err;
            }
        }
    }

    return EDPVS_OK;
}

void netif_update_worker_loop_cnt(void)
{
    lcore_stats[rte_lcore_id()].lcore_loop++;
}

static int get_lcore_stats(lcoreid_t cid, void **out, size_t *out_len)
{
    assert(out && out_len);

    netif_lcore_stats_get_t *get;
    struct netif_lcore_stats stats;

    get = rte_zmalloc(NULL, sizeof(struct netif_lcore_stats_get),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    if (is_isol_rxq_lcore(cid) || is_kni_lcore(cid)) {
        /* use write lock to ensure data safety */
        memcpy(&stats, &lcore_stats[cid], sizeof(stats));
    } else {
        int err;
        struct dpvs_msg *pmsg;
        struct dpvs_msg_reply *reply;

        pmsg = msg_make(MSG_TYPE_NETIF_LCORE_STATS, 0, DPVS_MSG_UNICAST,
                rte_lcore_id(), 0, NULL);
        if (unlikely(!pmsg)) {
            rte_free(get);
            return EDPVS_NOMEM;
        }

        err = msg_send(pmsg, cid, 0, &reply);
        if (EDPVS_OK != err) {
            msg_destroy(&pmsg);
            rte_free(get);
            return err;
        }

        assert(reply->len == sizeof(struct netif_lcore_stats));
        assert(reply->data);
        rte_memcpy(&stats, reply->data, sizeof(stats));

        msg_destroy(&pmsg);
    }

    get->lcore_id = cid;
    get->lcore_loop = stats.lcore_loop;
    get->pktburst = stats.pktburst;
    get->zpktburst = stats.zpktburst;
    get->fpktburst = stats.fpktburst;
    get->z2hpktburst = stats.z2hpktburst;
    get->h2fpktburst = stats.h2fpktburst;
    get->ipackets = stats.ipackets;
    get->ibytes = stats.ibytes;
    get->opackets = stats.opackets;
    get->obytes = stats.obytes;
    get->dropped = stats.dropped;

    *out = get;
    *out_len = sizeof(netif_lcore_stats_get_t);

    return EDPVS_OK;
}

static int get_port_list(nsid_t nsid, void **out, size_t *out_len)
{
    int i, cnt = 0;
    size_t len;
    struct netif_port *port;
    netif_nic_list_get_t *get;

    assert(out && out_len);

    len = sizeof(netif_nic_list_get_t) + g_nports * sizeof(struct port_id_name);
    get = rte_zmalloc(NULL, len, RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    get->phy_pid_base = phy_pid_base;
    get->phy_pid_end = phy_pid_end;

    for (i = 0; i < NETIF_PORT_TABLE_BUCKETS; i++) {
        rte_rwlock_read_lock(&port_rwlock[i]);
        list_for_each_entry(port, &port_tab[i], list) {
            if (nsid != NAMESPACE_ID_ALL && port->nsid != nsid) {
                continue;
            } 
            get->idname[cnt].id = port->id;
            snprintf(get->idname[cnt].name, sizeof(get->idname[cnt].name),
                    "%s", port->name);
            cnt++;
            if (cnt > g_nports) {
                RTE_LOG(ERR, NETIF, "%s: Too many ports in port_tab than expected!\n",
                        __func__);
                break;
            }
        }
        rte_rwlock_read_unlock(&port_rwlock[i]);
    }

    get->nic_num = cnt;

    *out = get;
    *out_len = len;

    return EDPVS_OK;
}

static int get_port_basic(struct netif_port *port, void **out, size_t *out_len)
{
    struct rte_eth_link link;
    netif_nic_basic_get_t *get;
    bool promisc;
    bool allmulticast;
    int err;

    get = rte_zmalloc(NULL, sizeof(netif_nic_basic_get_t),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    err = netif_get_link(port, &link);
    if (err != EDPVS_OK) {
        rte_free(get);
        return err;
    }

    get->port_id = port->id;
    strncpy(get->name, port->name, sizeof(get->name));
    get->nrxq = port->nrxq;
    get->ntxq = port->ntxq;
    rte_ether_format_addr(get->addr, sizeof(get->addr), &port->addr);

    get->socket_id = port->socket;
    get->mtu = port->mtu;

    get->link_speed = link.link_speed;

    switch (link.link_status) {
        case RTE_ETH_LINK_UP:
            snprintf(get->link_status, sizeof(get->link_status), "%s", "UP");
            break;
        case RTE_ETH_LINK_DOWN:
            snprintf(get->link_status, sizeof(get->link_status), "%s", "DOWN");
            break;
    }

    switch (link.link_duplex) {
        case RTE_ETH_LINK_HALF_DUPLEX:
            snprintf(get->link_duplex, sizeof(get->link_duplex), "%s", "half-duplex");
            break;
        case RTE_ETH_LINK_FULL_DUPLEX:
            snprintf(get->link_duplex, sizeof(get->link_duplex), "%s", "full-duplex");
            break;
    }

    switch (link.link_autoneg) {
        case RTE_ETH_LINK_FIXED:
            snprintf(get->link_autoneg, sizeof(get->link_autoneg), "%s", "fixed-nego");
            break;
        case RTE_ETH_LINK_AUTONEG:
            snprintf(get->link_autoneg, sizeof(get->link_autoneg), "%s", "auto-nego");
            break;
    }

    err = netif_get_promisc(port, &promisc);
    if (err != EDPVS_OK) {
        rte_free(get);
        return err;
    }
    get->promisc = promisc ? 1 : 0;

    err = netif_get_allmulticast(port, &allmulticast);
    if (err != EDPVS_OK) {
        rte_free(get);
        return err;
    }
    get->allmulticast = allmulticast ? 1 : 0;

    if (port->flag & NETIF_PORT_FLAG_FORWARD2KNI)
        get->fwd2kni = 1;
    if (port->flag & NETIF_PORT_FLAG_TC_EGRESS)
        get->tc_egress= 1;
    if (port->flag & NETIF_PORT_FLAG_TC_INGRESS)
        get->tc_ingress = 1;
    if (port->flag & NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD)
        get->ol_rx_ip_csum = 1;
    if (port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD)
        get->ol_tx_ip_csum = 1;
    if (port->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD)
        get->ol_tx_tcp_csum = 1;
    if (port->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)
        get->ol_tx_udp_csum = 1;
    if (port->flag & NETIF_PORT_FLAG_LLDP)
        get->lldp = 1;
    if (port->flag & NETIF_PORT_FLAG_TX_MBUF_FAST_FREE)
        get->ol_tx_fast_free = 1;

    *out = get;
    *out_len = sizeof(netif_nic_basic_get_t);

    return EDPVS_OK;
}

static inline void copy_dev_info(struct netif_nic_dev_get *get,
        const struct rte_eth_dev_info *dev_info)
{
    if (dev_info->driver_name)
        strncpy(get->driver_name, dev_info->driver_name, sizeof(get->driver_name));
    get->if_index = dev_info->if_index;
    get->min_rx_bufsize = dev_info->min_rx_bufsize;
    get->max_rx_pktlen = dev_info->max_rx_pktlen;
    get->max_rx_queues = dev_info->max_rx_queues;
    get->max_tx_queues = dev_info->max_tx_queues;
    get->max_mac_addrs = dev_info->max_mac_addrs;
    get->max_vfs = dev_info->max_vfs;
    get->max_vmdq_pools = dev_info->max_vmdq_pools;
    get->rx_offload_capa = dev_info->rx_offload_capa;
    get->tx_offload_capa = dev_info->tx_offload_capa;
    get->reta_size = dev_info->reta_size;
    get->hash_key_size = dev_info->hash_key_size;
    get->flow_type_rss_offloads = dev_info->flow_type_rss_offloads;
    get->vmdq_queue_base = dev_info->vmdq_queue_base;
    get->vmdq_queue_num = dev_info->vmdq_queue_num;
    get->vmdq_pool_base = dev_info->vmdq_pool_base;
    get->rx_desc_lim_nb_max = dev_info->rx_desc_lim.nb_max;
    get->rx_desc_lim_nb_min = dev_info->rx_desc_lim.nb_min;
    get->rx_desc_lim_nb_align = dev_info->rx_desc_lim.nb_align;
    get->tx_desc_lim_nb_max = dev_info->tx_desc_lim.nb_max;
    get->tx_desc_lim_nb_min = dev_info->tx_desc_lim.nb_min;
    get->tx_desc_lim_nb_align = dev_info->tx_desc_lim.nb_align;
    get->speed_capa = dev_info->speed_capa;
}

static int get_port_ext_info(struct netif_port *port, void **out, size_t *out_len)
{
    assert(out || out_len);

    struct rte_eth_dev_info dev_info = { 0 };
    netif_nic_ext_get_t *get, *new;
    char ctrlbuf[NETIF_CTRL_BUFFER_LEN];
    int len, naddr, err;
    size_t offset = 0;

    get = rte_zmalloc(NULL, sizeof(netif_nic_ext_get_t), 0);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    get->port_id = port->id;

    /* dev info */
    if (is_physical_port( port->id)) {
        rte_eth_dev_info_get(port->id, &dev_info);
        copy_dev_info(&get->dev_info, &dev_info);
    }

    /* mc_list */
    len = NETIF_CTRL_BUFFER_LEN;
    err = netif_mc_print(port, ctrlbuf, &len, &naddr);
    if (unlikely(EDPVS_OK != err))
        goto errout;

    new = rte_realloc(get, sizeof(netif_nic_ext_get_t) + offset + len + 1, 0);
    if (unlikely(!new)) {
        err = EDPVS_NOMEM;
        goto errout;
    }
    get = new;

    get->mc_list.data_offset = offset;
    get->mc_list.data_len = len;
    get->mc_list.naddr = naddr;
    memcpy(&get->data[offset], ctrlbuf, len);
    offset += len;

    get->data[offset] = '\0';
    offset++;

    get->datalen = offset;

    *out = get;
    *out_len = sizeof(netif_nic_ext_get_t) + get->datalen;

    return EDPVS_OK;

errout:
    rte_free(get);
    return err;
}

static inline void copy_port_stats(netif_nic_stats_get_t *get,
        const struct rte_eth_stats *stats)
{
    get->ipackets = stats->ipackets;
    get->opackets = stats->opackets;
    get->ibytes = stats->ibytes;
    get->obytes = stats->obytes;
    get->imissed = stats->imissed;
    get->ierrors = stats->ierrors;
    get->oerrors = stats->oerrors;
    get->rx_nombuf = stats->rx_nombuf;
    memcpy(&get->q_ipackets, &stats->q_ipackets, sizeof(stats->q_ipackets));
    memcpy(&get->q_opackets, &stats->q_opackets, sizeof(stats->q_opackets));
    memcpy(&get->q_ibytes, &stats->q_ibytes, sizeof(stats->q_ibytes));
    memcpy(&get->q_obytes, &stats->q_obytes, sizeof(stats->q_obytes));
    memcpy(&get->q_errors, &stats->q_errors, sizeof(stats->q_errors));
}

static int get_port_stats(struct netif_port *port, void **out, size_t *out_len)
{
    assert(out && out_len);

    int err;
    struct rte_eth_stats stats;
    netif_nic_stats_get_t *get;

    err = netif_get_stats(port, &stats);
    if (err != EDPVS_OK)
        return err;

    get = rte_zmalloc(NULL, sizeof(netif_nic_stats_get_t),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!get))
        return EDPVS_NOMEM;

    get->port_id = port->id;
    get->mbuf_avail = rte_mempool_avail_count(port->mbuf_pool);
    get->mbuf_inuse = rte_mempool_in_use_count(port->mbuf_pool);

    copy_port_stats(get, &stats);

    *out = get;
    *out_len = sizeof(netif_nic_stats_get_t);

    return EDPVS_OK;
}

static int get_port_xstats(struct netif_port *port, void **out, size_t *out_len)
{
    int err;
    assert(out && out_len);

    netif_nic_xstats_get_t *get;
    err = netif_get_xstats(port, &get);
    if (err != EDPVS_OK) {
        if (err == EDPVS_NOTSUPP)
            return EDPVS_OK;
        return err;
    }

    *out = get;
    *out_len = sizeof(netif_nic_xstats_get_t) + get->nentries * sizeof(struct netif_nic_xstats_entry);

    return EDPVS_OK;
}


static int netif_sockopt_get(sockoptid_t opt, const void *in, size_t inlen,
                             void **out, size_t *outlen)
{
    int ret = EDPVS_OK;
    lcoreid_t cid;
    char *name;
    struct netif_port *port;

    if (!out || !outlen)
        return EDPVS_INVAL;
    *out = NULL;
    *outlen = 0;

    switch (opt) {
        case SOCKOPT_NETIF_GET_LCORE_MASK:
            ret = get_lcore_mask(out, outlen);
            break;
        case SOCKOPT_NETIF_GET_LCORE_BASIC:
            if (!in || inlen != sizeof(lcoreid_t))
                return EDPVS_INVAL;
            cid = *(lcoreid_t *)in;
            if (!is_lcore_id_valid(cid))
                return EDPVS_INVAL;
            ret = get_lcore_basic(cid, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_LCORE_STATS:
            if (!in || inlen != sizeof(lcoreid_t))
                return EDPVS_INVAL;
            cid = *(lcoreid_t *)in;
            if (!is_lcore_id_valid(cid))
                return EDPVS_INVAL;
            ret = get_lcore_stats(cid, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_LIST:
            if (!in || inlen != sizeof(nsid_t))
                return EDPVS_INVAL;
            ret = get_port_list(*(nsid_t *)in, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_BASIC:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_port_basic(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_STATS:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_port_stats(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_XSTATS:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_port_xstats(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_PORT_EXT_INFO:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = get_port_ext_info(port, out, outlen);
            break;
        case SOCKOPT_NETIF_GET_BOND_STATUS:
            ret = EDPVS_NOTSUPP;
            break;
        case SOCKOPT_NETIF_GET_MADDR:
            if (!in)
                return EDPVS_INVAL;
            name = (char *)in;
            port = netif_port_get_by_name(name);
            if (!port)
                return EDPVS_NOTEXIST;
            ret = netif_get_multicast_addrs(port, out, outlen);
            break;
        default:
            RTE_LOG(WARNING, NETIF,
                    "[%s] invalid netif get cmd: %d\n", __func__, opt);
            ret = EDPVS_NOTSUPP;
            break;
    }

    if (EDPVS_OK != ret)
        RTE_LOG(ERR, NETIF, "[%s] %s for netif sockmsg opt %d)\n",
                __func__, dpvs_strerror(ret), opt);

    return ret;
}

static int set_lcore(const netif_lcore_set_t *lcore_cfg)
{
    assert(lcore_cfg);

    return EDPVS_OK;
}

static int set_port(struct netif_port *port, const netif_nic_set_t *port_cfg)
{
    struct rte_ether_addr ea;
    assert(port_cfg);

    if (port_cfg->promisc_on) {
        if (rte_eth_promiscuous_get(port->id) != 1)
            rte_eth_promiscuous_enable(port->id);
        RTE_LOG(INFO, NETIF, "[%s] promiscuous mode for %s enabled\n", __func__, port_cfg->pname);
    } else if (port_cfg->promisc_off) {
        if (rte_eth_promiscuous_get(port->id) != 0)
            rte_eth_promiscuous_disable(port->id);
        RTE_LOG(INFO, NETIF, "[%s] promiscuous mode for %s disabled\n", __func__, port_cfg->pname);
    }

    if (port_cfg->allmulticast_on) {
        if (rte_eth_allmulticast_get(port->id) != 1)
            rte_eth_allmulticast_enable(port->id);
        RTE_LOG(INFO, NETIF, "[%s] allmulticast for %s enabled\n", __func__, port_cfg->pname);
    } else if (port_cfg->allmulticast_off) {
        if (rte_eth_allmulticast_get(port->id) != 0) {
            rte_eth_allmulticast_disable(port->id);
            netif_set_mc_list(port);
        }
        RTE_LOG(INFO, NETIF, "[%s] allmulticast for %s disabled\n", __func__, port_cfg->pname);
    }

    if (port_cfg->forward2kni_on) {
        port->flag |= NETIF_PORT_FLAG_FORWARD2KNI;
        RTE_LOG(INFO, NETIF, "[%s] forward2kni mode for %s enabled\n",
            __func__, port_cfg->pname);
    } else if (port_cfg->forward2kni_off) {
        port->flag &= ~(NETIF_PORT_FLAG_FORWARD2KNI);
        RTE_LOG(INFO, NETIF, "[%s] forward2kni mode for %s disabled\n",
            __func__, port_cfg->pname);
    }

    if (port_cfg->link_status_up) {
        int err;
        struct rte_eth_link link;
        err = rte_eth_dev_set_link_up(port->id);
        rte_eth_link_get(port->id, &link);
        if (link.link_status == RTE_ETH_LINK_DOWN) {
            RTE_LOG(WARNING, NETIF, "set %s link up [ FAIL ] -- %d\n",
                    port_cfg->pname, err);
        } else {
            RTE_LOG(INFO, NETIF, "set %s link up [ OK ]"
                    " --- speed %dMbps %s-duplex %s-neg\n",
                    port_cfg->pname, link.link_speed,
                    link.link_duplex ? "full" : "half",
                    link.link_autoneg ? "auto" : "fixed");
        }
    } else if (port_cfg->link_status_down) {
        int err;
        struct rte_eth_link link;
        err = rte_eth_dev_set_link_down(port->id);
        rte_eth_link_get(port->id, &link);
        if (link.link_status == RTE_ETH_LINK_UP) {
            RTE_LOG(WARNING, NETIF, "set %s link down [ FAIL ] -- %d\n",
                    port_cfg->pname, err);
        } else {
            RTE_LOG(INFO, NETIF, "set %s link down [ OK ]\n", port_cfg->pname);
        }
    }

    memset(&ea, 0, sizeof(ea));
    sscanf(port_cfg->macaddr, "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned *)&ea.addr_bytes[0],
            (unsigned *)&ea.addr_bytes[1],
            (unsigned *)&ea.addr_bytes[2],
            (unsigned *)&ea.addr_bytes[3],
            (unsigned *)&ea.addr_bytes[4],
            (unsigned *)&ea.addr_bytes[5]);
    if (rte_is_valid_assigned_ether_addr(&ea)) {
        if (port->type == PORT_TYPE_GENERAL) {
            if (!rte_eth_dev_mac_addr_add(port->id, &ea, 0) &&
                    !rte_eth_dev_default_mac_addr_set(port->id, &ea)) {
                RTE_LOG(INFO, NETIF, "set %s's macaddr to be %s\n",
                        port->name, port_cfg->macaddr);
                port->addr = ea;
            } else {
                RTE_LOG(WARNING, NETIF, "fail to set %s's macaddr to be %s\n",
                        port->name, port_cfg->macaddr);
            }
        }
    }

    if (port_cfg->tc_egress_on)
        port->flag |= NETIF_PORT_FLAG_TC_EGRESS;
    else if (port_cfg->tc_egress_off)
        port->flag &= (~NETIF_PORT_FLAG_TC_EGRESS);

    if (port_cfg->tc_ingress_on)
        port->flag |= NETIF_PORT_FLAG_TC_INGRESS;
    else if (port_cfg->tc_ingress_off)
        port->flag &= (~NETIF_PORT_FLAG_TC_INGRESS);

    if (port_cfg->lldp_on)
        port->flag |= NETIF_PORT_FLAG_LLDP;
    else if (port_cfg->lldp_off)
        port->flag &= (~NETIF_PORT_FLAG_LLDP);

    return EDPVS_OK;
}

static int netif_sockopt_set(sockoptid_t opt, const void *in, size_t inlen)
{
    int ret;
    switch (opt) {
        case SOCKOPT_NETIF_SET_LCORE:
        {
            if (!in || inlen != sizeof(netif_lcore_set_t))
                return EDPVS_INVAL;
            if (!is_lcore_id_valid(((netif_lcore_set_t *)in)->cid))
                return EDPVS_INVAL;
            ret = set_lcore(in);
            break;
        }
        case SOCKOPT_NETIF_SET_PORT:
        {
            struct netif_port *port;
            if (!in || inlen != sizeof(netif_nic_set_t))
                return EDPVS_INVAL;
            port = netif_port_get_by_name(((netif_nic_set_t *)in)->pname);
            if (!port)
                return EDPVS_INVAL;
            ret = set_port(port, in);
            break;
        }
        case SOCKOPT_NETIF_SET_BOND:
        {
          return EDPVS_NOTSUPP; 
        }
        default:
            RTE_LOG(WARNING, NETIF, "[%s] invalid netif set cmd: %d\n", __func__, opt);
            return EDPVS_INVAL;
    }

    if (EDPVS_OK != ret)
        RTE_LOG(ERR, NETIF, "[%s] %s\n", __func__, dpvs_strerror(ret));

    return EDPVS_OK;
}

struct dpvs_sockopts netif_sockopt = {
    .version = SOCKOPT_VERSION,
    .get_opt_min = SOCKOPT_NETIF_GET_LCORE_MASK,
    .get_opt_max = SOCKOPT_NETIF_GET_MAX,
    .get = netif_sockopt_get,
    .set_opt_min = SOCKOPT_NETIF_SET_LCORE,
    .set_opt_max = SOCKOPT_NETIF_SET_MAX,
    .set = netif_sockopt_set,
};

int netif_ctrl_init(void)
{
    int err;

    if ((err = lcore_stats_msg_init()) != EDPVS_OK)
        return err;

    if ((err = netif_msg_init()) != EDPVS_OK)
        return err;

    if ((err = sockopt_register(&netif_sockopt)) != EDPVS_OK)
        return err;

    if ((err = kni_ctrl_init()) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}

int netif_ctrl_term(void)
{
    int err;

    if ((err = kni_ctrl_term()) != EDPVS_OK)
        return err;

    if ((err = sockopt_unregister(&netif_sockopt)) != EDPVS_OK)
        return err;

    if ((err = netif_msg_term()) != EDPVS_OK)
        return err;

    if ((err = lcore_stats_msg_term()) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}
