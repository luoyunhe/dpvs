#include "virtio_user.h"
#include "conf/common.h"
#include "conf/sockopts.h"
#include "conf/virtio_user.h"
#include "ctrl.h"
#include "generic/rte_atomic.h"
#include "generic/rte_rwlock.h"
#include "global_data.h"
#include "kni.h"
#include "list.h"
#include "namespace.h"
#include "netif.h"
#include "rte_dev.h"
#include "rte_ether.h"
#include "rte_lcore.h"
#include "rte_malloc.h"
#include "rte_memcpy.h"
#include <assert.h>
#include <linux/if_link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#define RTE_LOGTYPE_VIRTIO_USER       RTE_LOGTYPE_USER1

static struct list_head ongoing_list;
static rte_rwlock_t ongoing_list_lock;

struct ongoing_item {
    char             name[16];
    struct list_head list;
};

static int is_ongoing(const char *name) {
    struct ongoing_item *item;
    list_for_each_entry(item, &ongoing_list, list) {
        if (!strcmp(item->name, name))
            return 1;
    } 
    return 0;
}

static int add_ongoing(const char *name) {
    struct ongoing_item *item;
    rte_rwlock_write_lock(&ongoing_list_lock);
    if (is_ongoing(name)) {
        rte_rwlock_write_unlock(&ongoing_list_lock);
        return EDPVS_EXIST;
    }
    item = rte_zmalloc(NULL, sizeof(item->name), 0);
    if (item == NULL) {
        rte_rwlock_write_unlock(&ongoing_list_lock);
        return EDPVS_NOMEM;
    }
    strncpy(item->name, name, sizeof(item->name)-1);
    list_add_tail(&item->list, &ongoing_list);
    rte_rwlock_write_unlock(&ongoing_list_lock);
    return EDPVS_OK;
}

static void remove_ongoing(const char *name) {
    struct ongoing_item *item, *next;
    if (name == NULL) {
        return;
    }
    rte_rwlock_read_lock(&ongoing_list_lock);
    list_for_each_entry_safe(item, next, &ongoing_list, list) {
        if (!strcmp(item->name, name)) {
            list_del_init(&item->list);
            rte_free(item);
            rte_rwlock_read_unlock(&ongoing_list_lock);
            return;
        }
    }
    rte_rwlock_read_unlock(&ongoing_list_lock);
}

static int virtio_user_msg_seq(void)
{
    static rte_atomic32_t seq;
    rte_atomic32_inc(&seq);
    return rte_atomic32_read(&seq);
}

static void get_virtio_user_name(const char *name, char *out) {
    snprintf(out, 32, "virtio_user-%s", name);
}

int remove_virtio_user(struct netif_port *port) {
    int ret;
    char portname[32];
    get_virtio_user_name(port->name, portname);
    ret = netif_port_stop(port);
    if (ret)
        RTE_LOG(WARNING, VIRTIO_USER, "[%s] failed to stop port, error code = %d\n", __func__, ret);

    ret = kni_del_dev(port);
    if (ret)
        RTE_LOG(WARNING, VIRTIO_USER, "[%s] failed to del kni dev, error code = %d\n", __func__, ret);

    ret = rte_eal_hotplug_remove("vdev", portname);
    if (ret)
        RTE_LOG(WARNING, VIRTIO_USER, "[%s] failed to hotplug remove port, error code = %d\n", __func__, ret);

    ret = netif_port_unregister(port);
    if (ret) {
        RTE_LOG(ERR, VIRTIO_USER, "[%s] failed to unrigister port, error code = %d\n", __func__, ret);
        return ret;
    }
    netif_free(port);


    return EDPVS_OK;
}

static void* add_virtio_user(void * arg) {
    int ret = EDPVS_OK;
    int ret2 = EDPVS_OK;
    char portname[32];
    char portargs[256];
    uint16_t port_id;
    struct netif_port *port;
    struct rte_ether_addr mac_addr;
    struct dpvs_msg *msg;
    struct dpvs_sock_msg *sock_msg = (struct dpvs_sock_msg*) arg;
    struct virtio_user_param *param = (struct virtio_user_param*)sock_msg->data;
    int queue = g_slave_lcore_mask;
    rte_memcpy(&mac_addr, param->mac, sizeof(struct rte_ether_addr));
    get_virtio_user_name(param->name, portname);
    // 创建虚拟设备参数，指定路径，设备名称，mac地址等
    snprintf(portargs, sizeof(portargs), 
    "path=%s,packed_vq=1,speed=25000,server=1,queues=%d,queue_size=1024,mac="RTE_ETHER_ADDR_PRT_FMT,
            param->path, queue, RTE_ETHER_ADDR_BYTES(&mac_addr));
    remove(param->path);
    // 把设备加入到系统
    ret = rte_eal_hotplug_add("vdev", portname, portargs);
    if (ret != 0) {
        RTE_LOG(INFO, VIRTIO_USER, "[%s] fail to add vdev, error code = %d\n",
                __func__, ret);
        ret = EDPVS_DPDKAPIFAIL;
        goto exit_remove_ongoing;
    }
    // 获取port id
    if (rte_eth_dev_get_port_by_name(portname, &port_id) != 0) {
        RTE_LOG(ERR, VIRTIO_USER, "[%s] failed to get port by name %s\n",
                                __func__, portname);
        goto hotplug_remove;
    }
    RTE_LOG(INFO, VIRTIO_USER, "[%s] hotplug add port %s success, port id %d\n",
                                __func__, param->name, port_id);
    
    // 分配结构
    port = netif_alloc(param->nsid, port_id, 0, param->name, 0, 0, dpdk_port_setup);
    if (!port) {
        ret = EDPVS_DPDKAPIFAIL;
        goto hotplug_remove;
    }

    if (kni_add_dev(port, param->name) < 0) {
        RTE_LOG(ERR, VIRTIO_USER, "[%s] failed to add kni dev for %s\n", __func__, param->name);
        ret = EDPVS_DPDKAPIFAIL;
        goto free_netif;
    }
    ret = netif_port_register(port);
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, VIRTIO_USER, "[%s] failed to register port for %s\n", __func__, param->name);
        goto del_kni; 
    }
    // start port
    ret = netif_port_start(port);
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, VIRTIO_USER, "[%s] failed to start port %s\n", __func__, port->name);
        goto stop_port;
    }
    // callback to master lcore
    msg = msg_make(MSG_TYPE_VIRTIO_USER_ADD, virtio_user_msg_seq(), DPVS_MSG_UNICAST,
        g_master_lcore_id, sizeof(struct netif_port*), &port);
    if (!msg) {
        ret = EDPVS_NOMEM;
        goto stop_port;
    }
    ret = msg_send(msg, g_master_lcore_id, DPVS_MSG_F_ASYNC, NULL);
    if (ret != EDPVS_OK) {
        RTE_LOG(INFO, VIRTIO_USER, "[%s] fail to send message, error code = %d\n", __func__, ret);
        msg_destroy(&msg);
        goto stop_port;
    }
    msg_destroy(&msg);
    goto exit_remove_ongoing;

stop_port:
    ret2 = netif_port_stop(port);
    if (ret2)
        RTE_LOG(WARNING, VIRTIO_USER, "[%s] failed to stop port, error code = %d\n", __func__, ret2);
    ret2 = netif_port_unregister(port);
    if (ret2)
        RTE_LOG(WARNING, VIRTIO_USER, "[%s] failed to unrigister port, error code = %d\n", __func__, ret2);

del_kni:
    ret2 = kni_del_dev(port);
    if (ret2)
        RTE_LOG(WARNING, VIRTIO_USER, "[%s] failed to del kni dev, error code = %d\n", __func__, ret2);

free_netif:
    netif_free(port);

hotplug_remove:
    ret2 = rte_eal_hotplug_remove("vdev", portname);
    if (ret2)
        RTE_LOG(WARNING, VIRTIO_USER, "[%s] failed to hotplug remove port, error code = %d\n", __func__, ret2);

exit_remove_ongoing:
    remove_ongoing(param->name);
    ret2= reply_msg(sock_msg, ret);
    if (ret2)
        RTE_LOG(WARNING, VIRTIO_USER, "[%s] fail to reply msg, error code = %d\n", __func__, ret2);
    rte_free(arg);
    return NULL;
}

static int virtio_user_add_msg_cb(struct dpvs_msg *msg)
{
    int ret = EDPVS_OK;
    struct netif_port *port = *((struct netif_port**) msg->data);
    /* ipv6 default addresses initialization */
    if ((ret = idev_addr_init(port->in_ptr)) != EDPVS_OK) {
        RTE_LOG(WARNING, VIRTIO_USER, "%s: idev_addr_init failed -- %d(%s)\n",
                __func__, ret, dpvs_strerror(ret));
        return ret;
    }

    return netif_add(port);
}


// 创建virtio_user比较耗时大，通过线程处理
static int virtio_user_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    int ret;
    pthread_t thread;
    struct dpvs_sock_msg *msg, *msg_copy;
    if (size != sizeof(struct virtio_user_param))
        return EDPVS_INVAL;
    msg = msg_from_data(conf);
    
    struct virtio_user_param *param;
    param = (struct virtio_user_param*)msg->data;
    if (strlen(param->name) == 0 || strlen(param->path) == 0)
        return EDPVS_INVAL;
    if (netif_port_get_by_name(param->name))
        return EDPVS_EXIST;
    ret = add_ongoing(param->name);
    if (ret != EDPVS_OK)
        return ret;

    if (!namespace_get(param->nsid))
        return EDPVS_NS_NOTEXIST;

    msg_copy = rte_malloc("viriot_param", size+sizeof(struct dpvs_sock_msg), 0);
    if (msg_copy == NULL) {
        return EDPVS_NOMEM;
    }
    rte_memcpy(msg_copy, msg, size+sizeof(struct dpvs_sock_msg));

    ret = pthread_create(&thread, NULL, add_virtio_user, msg_copy);
    if (ret != 0) {
        return EDPVS_SYSCALL;
    }
    return EDPVS_ONGOING;
}

static int virtio_user_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    return EDPVS_NOTSUPP;
}

static struct dpvs_sockopts virtio_user_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_VIRTIO_USER_ADD,
    .set_opt_max    = SOCKOPT_SET_VIRTIO_USER_ADD,
    .set            = virtio_user_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_VIRTIO_USER_NONE,
    .get_opt_max    = SOCKOPT_GET_VIRTIO_USER_NONE,
    .get            = virtio_user_sockopt_get,
};

static struct dpvs_msg_type virtio_user_msg_type = {
    .type = MSG_TYPE_VIRTIO_USER_ADD,
    .mode = DPVS_MSG_UNICAST,
    .prio = MSG_PRIO_NORM,
    .unicast_msg_cb = virtio_user_add_msg_cb,
    .multicast_msg_cb = NULL,
};

int virtio_user_init(void)
{
    int err;

    rte_rwlock_init(&ongoing_list_lock);
    INIT_LIST_HEAD(&ongoing_list);

    virtio_user_msg_type.cid = rte_get_main_lcore();
    err = msg_type_register(&virtio_user_msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, VIRTIO_USER, "%s: fail to register MSG_TYPE_VIRTIO_USER_ADD msg type.\n", __func__);
        return err;
    }

    
    if ((err = sockopt_register(&virtio_user_sockopts)) != EDPVS_OK) {
        return err;
    }

    return EDPVS_OK;
}

int virtio_user_term(void)
{
    int err;

    err = sockopt_unregister(&virtio_user_sockopts);
    if (err != EDPVS_OK)
        return err;

    err = msg_type_unregister(&virtio_user_msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, VIRTIO_USER, "%s: fail to unregister MSG_TYPE_VIRTIO_USER_ADD msg type.\n", __func__);
        return err;
    }


    return EDPVS_OK;
}
