#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "xdp_lb_common.h"

#define CONFIG_DIR "/etc/xdp_lb"
#define CONFIG_PATH CONFIG_DIR "/xdp_lb.json"
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define fail(...) (fprintf(stderr, __VA_ARGS__), fputc('\n', stderr), -1)

static const char *map_dir = "/sys/fs/bpf/xdp_lb_test/maps";
static const char *device_ip = "192.168.100.20";

static const char usage[] =
    "usage: xdp_lb_ctl add-vip <vip> <port> <tcp|udp> <backend_ip>...\n"
    "       xdp_lb_ctl del-vip <vip> <port> <tcp|udp>\n"
    "       xdp_lb_ctl fragment <on|off>\n"
    "       xdp_lb_ctl pmtu <on|off>\n"
    "       xdp_lb_ctl apply\n";

struct service {
    struct vip_key vip;
    struct vip_value value;
    struct backend backends[MAX_BACKENDS_PER_VIP];
};

static struct device_config device;
static struct service services[MAX_VIPS];
static size_t service_count;

static int find_service(const struct vip_key *vip)
{
    for (size_t index = 0; index < service_count; index++)
        if (!memcmp(&services[index].vip, vip, sizeof(*vip)))
            return index;
    return -1;
}

static int parse_service(json_t *item, struct service *service)
{
    const char *vip, *protocol;
    json_t *backends, *backend;
    json_error_t error;
    size_t slot;
    int port;

    if (json_unpack_ex(item, &error, JSON_STRICT, "{s:s, s:i, s:s, s:o}", "vip", &vip,
                       "port", &port, "protocol", &protocol, "backends", &backends))
        return fail("%s", error.text);
    *service = (struct service){
        .vip.port = htons(port),
        .vip.protocol = strcmp(protocol, "udp") ? IPPROTO_TCP : IPPROTO_UDP,
        .value.backend_count = json_array_size(backends),
    };
    if (inet_pton(AF_INET, vip, &service->vip.address) != 1 || port < 1 || port > 65535 ||
        (strcmp(protocol, "tcp") && strcmp(protocol, "udp")))
        return fail("invalid VIP: %s %d %s", vip, port, protocol);
    if (!json_is_array(backends) || json_array_size(backends) > MAX_BACKENDS_PER_VIP)
        return fail("backends must be a list of at most %d addresses", MAX_BACKENDS_PER_VIP);
    json_array_foreach(backends, slot, backend)
        if (!json_is_string(backend) ||
            inet_pton(AF_INET, json_string_value(backend), &service->backends[slot].address) != 1)
            return fail("invalid backend address in %s", vip);
    return 0;
}

static int parse_config(json_t *root)
{
    json_t *list, *item;
    json_error_t error;
    int fragment, pmtu;
    size_t index;

    if (json_unpack_ex(root, &error, JSON_STRICT, "{s:b, s:b, s:o}", "fragment_handling",
                       &fragment, "icmp_pmtu", &pmtu, "services", &list))
        return fail("%s: %s", CONFIG_PATH, error.text);
    if (!json_is_array(list) || json_array_size(list) > MAX_VIPS)
        return fail("%s: services must be a list of at most %d entries", CONFIG_PATH, MAX_VIPS);
    device = (struct device_config){
        .fragment_handling_enabled = fragment,
        .icmp_pmtu_enabled = pmtu,
    };
    inet_pton(AF_INET, device_ip, &device.ip_address);
    json_array_foreach(list, index, item) {
        if (parse_service(item, &services[index]))
            return fail("  in %s services[%zu]", CONFIG_PATH, index);
    }
    service_count = json_array_size(list);
    return 0;
}

static int load_config(json_t **root)
{
    json_error_t error;

    if (access(CONFIG_PATH, F_OK))
        *root = json_pack("{s:b, s:b, s:[]}", "fragment_handling", 0, "icmp_pmtu", 0, "services");
    else if (!(*root = json_load_file(CONFIG_PATH, 0, &error)))
        return fail("%s:%d:%d: %s", CONFIG_PATH, error.line, error.column, error.text);
    return parse_config(*root);
}

static int save_config(json_t *root)
{
    mkdir(CONFIG_DIR, 0755);
    if (json_dump_file(root, CONFIG_PATH ".tmp", JSON_INDENT(2)) ||
        rename(CONFIG_PATH ".tmp", CONFIG_PATH))
        return fail("cannot save %s: %s", CONFIG_PATH, strerror(errno));
    return 0;
}

static int open_map(const char *name)
{
    char path[256];
    int fd;

    snprintf(path, sizeof(path), "%s/%s", map_dir, name);
    fd = bpf_obj_get(path);
    return fd < 0 ? fail("cannot open %s: %s", path, strerror(errno)) : fd;
}

/* VIPs are removed before the slots they count and written after them. */
static int sync_maps(void)
{
    int vip_fd = open_map("vip_map"), backend_fd = open_map("backend_map");
    int device_fd = open_map("device_ip_map");
    struct backend_key key; /* big enough for the keys of both maps */

    if (vip_fd < 0 || backend_fd < 0 || device_fd < 0)
        return -1;
    while (!bpf_map_get_next_key(vip_fd, NULL, &key))
        if (bpf_map_delete_elem(vip_fd, &key))
            goto error;
    while (!bpf_map_get_next_key(backend_fd, NULL, &key))
        if (bpf_map_delete_elem(backend_fd, &key))
            goto error;
    if (bpf_map_update_elem(device_fd, &(__u32){0}, &device, BPF_ANY))
        goto error;
    for (struct service *service = services; service < services + service_count; service++) {
        struct backend_key slot = { .vip = service->vip };

        for (; slot.slot < service->value.backend_count; slot.slot++)
            if (bpf_map_update_elem(backend_fd, &slot, &service->backends[slot.slot], BPF_ANY))
                goto error;
        if (bpf_map_update_elem(vip_fd, &service->vip, &service->value, BPF_ANY))
            goto error;
    }
    return 0;
error:
    return fail("cannot write maps: %s", strerror(errno));
}

/* add-vip passes backends and adds or replaces the service; del-vip passes none. */
static int edit_vip(json_t *root, char **args)
{
    json_t *list = json_object_get(root, "services");
    json_t *port = json_loads(args[1], JSON_DECODE_ANY, NULL);
    json_t *backends = json_array();
    struct service parsed;
    json_t *item;
    int index;

    if (!port)
        return fail("invalid port: %s", args[1]);
    for (char **backend = args + 3; *backend; backend++)
        json_array_append_new(backends, json_string(*backend));
    item = json_pack("{s:s, s:o, s:s, s:o}", "vip", args[0], "port", port,
                     "protocol", args[2], "backends", backends);
    if (parse_service(item, &parsed))
        return -1;

    index = find_service(&parsed.vip);
    if (args[3])
        return index < 0 ? json_array_append_new(list, item)
                         : json_array_set_new(list, index, item);
    if (index < 0)
        return fail("no such VIP: %s %s %s", args[0], args[1], args[2]);
    return json_array_remove(list, index);
}

static int set_toggle(json_t *root, const char *key, const char *value)
{
    if (strcmp(value, "on") && strcmp(value, "off"))
        return fail("invalid value: %s (expected on/off)", value);
    return json_object_set_new(root, key, json_boolean(!strcmp(value, "on")));
}

static const struct command {
    const char *name;
    int min_args, max_args;
    const char *toggle;
} commands[] = {
    { "add-vip", 4, INT_MAX, NULL },
    { "del-vip", 3, 3, NULL },
    { "fragment", 1, 1, "fragment_handling" },
    { "pmtu", 1, 1, "icmp_pmtu" },
    { "apply", 0, 0, NULL },
};

int main(int argc, char **argv)
{
    const struct command *command = commands, *end = commands + ARRAY_SIZE(commands);
    int edits = argc > 1 && strcmp(argv[1], "apply");
    json_t *root;

    while (command < end && strcmp(command->name, argc > 1 ? argv[1] : ""))
        command++;
    if (command == end || argc - 2 < command->min_args || argc - 2 > command->max_args) {
        fputs(usage, stderr);
        return 1;
    }

    if (load_config(&root))
        return 1;
    if (edits && (command->toggle ? set_toggle(root, command->toggle, argv[2])
                                  : edit_vip(root, argv + 2)))
        return 1;
    if (parse_config(root) || sync_maps() || (edits && save_config(root)))
        return 1;
    return 0;
}
