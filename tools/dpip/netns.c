#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "conf/common.h"
#include "dpip.h"
#include "sockopt.h"
#include "conf/namespace.h"

static void netns_help(void)
{
    fprintf(stderr,
        "Usage:\n"
        "    dpip netns { add | del | show } [ NAME ]\n"
        "\n"
        "Parameters:\n"
        "    NAME      := NAMESPACE NAME\n"
        );
}

static bool is_valid_name(const char* str) {
    while (*str) {
        if (!islower(*str) && !isdigit(*str) && *str != '_' && *str != '-') {
            return false;
        }
        str++;
    }
    return true;
}

static int netns_parse(struct dpip_obj *obj, struct dpip_conf *cf)
{
    struct netns_conf *conf = obj->param;

    memset(conf, 0, sizeof(*conf));

    if (cf->argc > 0) {
        snprintf(conf->name, NAMESPACE_MAX_NAME_LEN, "%s", CURRARG(cf));
        if (!is_valid_name(conf->name)) {
            fprintf(stderr, "invalid ns name %s, only (a-z|0-9|-|_) are allowed\n", conf->name);
            return EDPVS_INVAL;
        }
    }
    if ((cf->cmd == DPIP_CMD_ADD || cf->cmd == DPIP_CMD_DEL) &&
        !conf->name[0]) {
            fprintf(stderr, "NAME must be specified\n");
            return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

static int netns_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    return EDPVS_OK;
}

static void netns_dump(const struct netns_conf * conf, bool verbose)
{
    printf("%s (id: %d)\n", conf->name, conf->nsid);
}

static int netns_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    struct netns_conf *ns_conf = obj->param;
    int err, i;
    size_t size;
    struct netns_conf_header *conf_header;


    switch (cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_SET_NAMESPACE_ADD, ns_conf,
                               sizeof(struct netns_conf));
    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_SET_NAMESPACE_DEL, ns_conf,
                               sizeof(struct netns_conf));
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_SET_NAMESPACE_SHOW, ns_conf,
                              sizeof(struct netns_conf), (void **)&conf_header, &size);
        if (err != 0)
            return EDPVS_INVAL;

        if (size < sizeof(struct netns_conf_header) || 
            size != sizeof(struct netns_conf_header) + conf_header->cnt * sizeof(struct netns_conf)) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(conf_header);
            return EDPVS_INVAL;
        }

        for (i = 0; i < conf_header->cnt; i++)
            netns_dump(&conf_header->ns_list[i], conf->verbose);

        dpvs_sockopt_msg_free(conf_header);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

static struct netns_conf netns_conf = {
};

static struct dpip_obj dpip_netns = {
    .name   = "netns",
    .param  = &netns_conf,
    .help   = netns_help,
    .parse  = netns_parse,
    .check  = netns_check,
    .do_cmd = netns_do_cmd,
};

static void __init netns_init(void)
{
    dpip_register_obj(&dpip_netns);
}

static void __exit netns_exit(void)
{
    dpip_unregister_obj(&dpip_netns);
}
