#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

#include "conf/common.h"
#include "conf/namespace.h"
#include "conf/sockopts.h"
#include "list.h"
#include "namespace.h"
#include "netif.h"
#include "ctrl.h"
#include "dpdk.h"
#include "rte_lcore.h"
#include "rte_malloc.h"

#define RTE_LOGTYPE_NAMESPACE       RTE_LOGTYPE_USER1


#define NAMESPACE_TABLE_BUCKETS 64
#define NAMESPACE_TABLE_MASK (NAMESPACE_TABLE_BUCKETS - 1)
static struct list_head ns_tab[NAMESPACE_TABLE_BUCKETS];  /* hashed by id */
static struct list_head ns_ntab[NAMESPACE_TABLE_BUCKETS]; /* hashed by name */

static struct list_head ns_free_list;
static uint16_t g_ns_cnt = 0;

static int nsid_map[NETIF_MAX_PORTS];

void nsid_init(void)
{
    for (int i = 0; i < NETIF_MAX_PORTS; i++){
        nsid_map[i] = -1;
    }
}

nsid_t nsid_get(portid_t id)
{
    nsid_t nsid = nsid_map[id];
    assert(nsid >= 0 && nsid<=DPVS_MAX_NETNS);
    return nsid ;
}

void nsid_set(portid_t port_id, nsid_t ns_id)
{
    nsid_map[port_id] = ns_id;
}

static int ns_msg_seq(void)
{
    static uint32_t seq = 0;

    return seq++;
}

static inline int ns_tab_hashkey(portid_t id)
{
    return id & NAMESPACE_TABLE_MASK;
}

static unsigned int ns_ntab_hashkey(const char *name, size_t len)
{
    int i;
    unsigned int hash=1315423911;
    for (i = 0; i < len; i++)
    {
        if (name[i] == '\0')
            break;
        hash^=((hash<<5)+name[i]+(hash>>2));
    }

    return (hash % NAMESPACE_TABLE_BUCKETS);
}

static inline void ns_tab_init(void)
{
    int i;
    for (i = 0; i < NAMESPACE_TABLE_BUCKETS; i++)
        INIT_LIST_HEAD(&ns_tab[i]);
}

static inline void ns_ntab_init(void)
{
    int i;
    for (i = 0; i < NAMESPACE_TABLE_BUCKETS; i++)
        INIT_LIST_HEAD(&ns_ntab[i]);
}

struct namespace* namespace_get(nsid_t id)
{
    int hash = ns_tab_hashkey(id);
    struct namespace *ns;
    assert(id <= NAMESPACE_MAX_ID);

    list_for_each_entry(ns, &ns_tab[hash], list) {
        if (ns->id == id) {
            return ns;
        }
    }

    return NULL;
}

struct namespace* namespace_get_by_name(const char *name)
{
    int nhash;
    struct namespace *ns;

    if (!name || strlen(name) <= 0)
        return NULL;

    nhash = ns_ntab_hashkey(name, strlen(name));
    list_for_each_entry(ns, &ns_ntab[nhash], nlist) {
        if (!strcmp(ns->name, name)) {
            return ns;
        }
    }

    return NULL;
}

static inline struct namespace * retain_ns(const char *name) {
    struct namespace *ns;
    if (list_empty(&ns_free_list)) {
        return NULL;
    }
    ns = list_first_entry_or_null(&ns_free_list, struct namespace, list);
    if (ns != NULL) {
        list_del(&ns->list);
    }
    strcpy(ns->name, name);
    return ns;
} 

static inline void release_ns(struct namespace *ns) {
    nsid_t nsid = ns->id;
    memset(ns, 0, sizeof(struct namespace));
    ns->id = nsid;
    list_add_tail(&ns->list, &ns_free_list);
}

static int namespace_register(struct namespace *ns)
{
    struct namespace *cur;
    int hash, nhash;

    if (unlikely(NULL == ns))
        return EDPVS_INVAL;

    hash = ns_tab_hashkey(ns->id);
    list_for_each_entry(cur, &ns_tab[hash], list) {
        if (cur->id == ns->id || strcmp(cur->name, ns->name) == 0) {
            return EDPVS_EXIST;
        }
    }

    nhash = ns_ntab_hashkey(ns->name, sizeof(ns->name));
    list_for_each_entry(cur, &ns_ntab[nhash], nlist) {
        if (cur->id == ns->id || strcmp(cur->name, ns->name) == 0) {
            return EDPVS_EXIST;
        }
    }

    list_add_tail(&ns->list, &ns_tab[hash]);
    list_add_tail(&ns->nlist, &ns_ntab[nhash]);
    g_ns_cnt++;

    return EDPVS_OK;
}

static int namespace_unregister(struct namespace *ns)
{
    struct namespace *cur, *next;
    int ret1, ret2, hash, nhash;
    if (unlikely(NULL == ns))
        return EDPVS_INVAL;
    ret1 = ret2 = EDPVS_NOTEXIST;

    hash = ns_tab_hashkey(ns->id);
    list_for_each_entry_safe(cur, next, &ns_tab[hash], list) {
        if (cur->id == ns->id || strcmp(cur->name, ns->name) == 0) {
            list_del_init(&cur->list);
            ret1 = EDPVS_OK;
            break;
        }
    }

    nhash = ns_ntab_hashkey(ns->name, sizeof(ns->name));
    list_for_each_entry_safe(cur, next, &ns_ntab[nhash], nlist) {
        if (cur->id == ns->id || strcmp(cur->name, ns->name) == 0) {
            list_del_init(&cur->nlist);
            ret2 = EDPVS_OK;
            break;
        }
    }

    if (ret1 != EDPVS_OK || ret2 != EDPVS_OK)
        return EDPVS_NOTEXIST;
    g_ns_cnt--;
    return EDPVS_OK;
}

static int namespace_flush_msg_cb(struct dpvs_msg *msg)
{
    // todo
    printf("flush ns in lcore %d\n", rte_lcore_id());
    return EDPVS_OK;
}


static int namespace_sockopt_set(sockoptid_t opt, const void *in, size_t inlen)
{
    int ret = EDPVS_OK;
    struct namespace *ns = NULL;
    lcoreid_t cid = rte_lcore_id();
    struct dpvs_msg *msg;

    if (!in || inlen != sizeof(struct netns_conf))
        return EDPVS_INVAL;

    struct netns_conf * conf = (struct netns_conf*)in;

    if (conf->name[0] == '\0') {
        return EDPVS_INVAL;
    }
    printf("set ns %s\n", conf->name);

    switch (opt) {
        case SOCKOPT_SET_NAMESPACE_ADD:
        {
            if (namespace_get_by_name(conf->name)) {
                return EDPVS_EXIST;
            }
            ns = retain_ns(conf->name);
            if (ns == NULL) {
                return EDPVS_RESOURCE;
            }
            ret = namespace_register(ns);
            if (ret != EDPVS_OK) {
                release_ns(ns);
                return ret;
            }
            break;
        }
        case SOCKOPT_SET_NAMESPACE_DEL:
        {
            ns = namespace_get_by_name(conf->name);
            if (ns == NULL) {
                return EDPVS_NOTEXIST;
            }

            msg = msg_make(MSG_TYPE_NAMESPACE_FLUSH, ns_msg_seq(), DPVS_MSG_MULTICAST,
                cid, sizeof(nsid_t), &ns->id);
            ret = multicast_msg_send(msg, 0, NULL);
            if (ret != EDPVS_OK)
                RTE_LOG(INFO, NAMESPACE, "[%s] fail to send multicast message, error code = %d\n",
                                                                      __func__, ret);
            msg_destroy(&msg);
                                                          

            ret = namespace_unregister(ns);
            if (ret != EDPVS_OK)
                return ret;
            release_ns(ns);
            break;
        }
        default:
            RTE_LOG(WARNING, NETIF, "[%s] invalid netns set cmd: %d\n", __func__, opt);
            return EDPVS_INVAL;
    }
    return ret;
}

static int namespace_sockopt_get(sockoptid_t opt, const void *in, size_t inlen,
                             void **out, size_t *outlen)
{
    int ret = EDPVS_OK;
    int i, off = 0;
    struct namespace *ns;
    struct netns_conf_header *conf_header;

    if (!in || inlen != sizeof(struct netns_conf) || opt != SOCKOPT_SET_NAMESPACE_SHOW)
        return EDPVS_INVAL;

    struct netns_conf * conf = (struct netns_conf*)in;

    *out = rte_malloc(NULL, sizeof(struct netns_conf) * g_ns_cnt + sizeof(struct netns_conf_header), 0);
    if (!(*out))
        return EDPVS_NOMEM;
    conf_header = (struct netns_conf_header *)*out;
    if (g_ns_cnt == 0) {
        conf_header->cnt = 0;
        *outlen = sizeof(struct netns_conf) * conf_header->cnt + sizeof(struct netns_conf_header);
        return EDPVS_OK;
    }

    for (i = 0; i < NAMESPACE_TABLE_BUCKETS; i++) {
        list_for_each_entry(ns, &ns_tab[i], list) {
            if (conf->name[0] != '\0' && strncmp(conf->name, ns->name, sizeof(ns->name)))
                continue;
            strncpy(conf_header->ns_list[off].name, ns->name, sizeof(ns->name));
            conf_header->ns_list[off].nsid = ns->id;
            off++;
        }
    }
    conf_header->cnt = off;
    *outlen = sizeof(struct netns_conf) * conf_header->cnt + sizeof(struct netns_conf_header);
    assert(conf->name[0] == '\0' ? off == g_ns_cnt : true);

    return ret;
}

static struct dpvs_sockopts namespace_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_NAMESPACE_ADD,
    .set_opt_max    = SOCKOPT_SET_NAMESPACE_DEL,
    .set            = namespace_sockopt_set,
    .get_opt_min    = SOCKOPT_SET_NAMESPACE_SHOW,
    .get_opt_max    = SOCKOPT_SET_NAMESPACE_SHOW,
    .get            = namespace_sockopt_get,
};

static struct dpvs_msg_type namespace_msg_type = {
    .type = MSG_TYPE_NAMESPACE_FLUSH,
    .mode = DPVS_MSG_MULTICAST,
    .prio = MSG_PRIO_NORM,
    .unicast_msg_cb = namespace_flush_msg_cb,
    .multicast_msg_cb = NULL,
};

int namespace_init(void)
{
    int err;
    nsid_t nsid;
    struct namespace *ns, *ns_list;

    INIT_LIST_HEAD(&ns_free_list);
    ns_list = rte_zmalloc(NULL,
    sizeof(struct namespace[DPVS_MAX_NETNS]), RTE_CACHE_LINE_SIZE);
    if (ns_list == NULL) {
        return EDPVS_NOMEM;
    }
    for (nsid = 0; nsid < DPVS_MAX_NETNS; nsid++) {
        ns = &ns_list[nsid];
        ns->id = nsid;
        list_add_tail(&ns->list, &ns_free_list);
    }

    ns_tab_init();
    ns_ntab_init();

    err = msg_type_mc_register(&namespace_msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, NAMESPACE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    if ((err = sockopt_register(&namespace_sockopts)) != EDPVS_OK) {
        return err;
    }

    return EDPVS_OK;
}

int namespace_term(void)
{
    int err;

    err = sockopt_unregister(&namespace_sockopts);
    if (err != EDPVS_OK)
        return err;

    err = msg_type_mc_unregister(&namespace_msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, NAMESPACE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    return EDPVS_OK;
}
