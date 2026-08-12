#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PIN_DIR "/sys/fs/bpf"
#define VIP_MAP_PATH PIN_DIR "/vip_map"
#define SERVER_MAP_PATH PIN_DIR "/server_map"
#define TUNNEL_CONFIG_MAP_PATH PIN_DIR "/tunnel_config_map"
#define MAX_SERVERS_PER_VIP 64

struct vip_key {
    __be32 address;
    __be16 port;
    __u8 protocol;
    __u8 padding;
};

struct vip_config {
    __u32 server_count;
};

struct server_key {
    struct vip_key vip;
    __u32 slot;
};

struct server {
    __be32 address;
    __u8 mac_address[ETH_ALEN];
};

struct tunnel_config {
    __be32 source_address;
};

static void print_usage(const char *program_name)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s add-vip <vip_ip> <vip_port> <tcp|udp> <server_count>\n"
            "  %s del-vip <vip_ip> <vip_port> <tcp|udp>\n"
            "  %s add-b-server <vip_ip> <vip_port> <tcp|udp> <slot> <b_ip> <mac>\n"
            "  %s del-b-server <vip_ip> <vip_port> <tcp|udp> <slot>\n"
            "  %s set-tunnel-source <source_ip>\n",
            program_name, program_name, program_name, program_name,
            program_name);
}

static int parse_protocol(const char *text, __u8 *protocol)
{
    if (!strcmp(text, "tcp")) {
        *protocol = IPPROTO_TCP;
        return 0;
    }

    if (!strcmp(text, "udp")) {
        *protocol = IPPROTO_UDP;
        return 0;
    }

    fprintf(stderr, "invalid protocol: %s\n", text);
    return -1;
}

static int parse_uint16(const char *text, __u16 *result)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno || end == text || *end != '\0' || parsed > 65535)
        return -1;

    *result = (__u16)parsed;
    return 0;
}

static int parse_uint32(const char *text, __u32 *result)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno || end == text || *end != '\0' || parsed > 0xffffffffUL)
        return -1;

    *result = (__u32)parsed;
    return 0;
}

static int parse_mac_address(const char *text, __u8 mac_address[ETH_ALEN])
{
    unsigned int bytes[ETH_ALEN];
    int consumed = 0;

    if (sscanf(text, "%x:%x:%x:%x:%x:%x%n",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5], &consumed) != ETH_ALEN ||
        text[consumed] != '\0')
        return -1;

    for (int i = 0; i < ETH_ALEN; i++) {
        if (bytes[i] > 0xff)
            return -1;
        mac_address[i] = (__u8)bytes[i];
    }

    return 0;
}

static int parse_vip_key(char **arguments, struct vip_key *vip)
{
    __u16 port;

    memset(vip, 0, sizeof(*vip));

    if (inet_pton(AF_INET, arguments[0], &vip->address) != 1) {
        fprintf(stderr, "invalid VIP address: %s\n", arguments[0]);
        return -1;
    }

    if (parse_uint16(arguments[1], &port)) {
        fprintf(stderr, "invalid VIP port: %s\n", arguments[1]);
        return -1;
    }

    if (parse_protocol(arguments[2], &vip->protocol))
        return -1;

    vip->port = htons(port);
    return 0;
}

static int open_pinned_map(const char *path)
{
    int fd = bpf_obj_get(path);

    if (fd < 0)
        fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));

    return fd;
}

static int add_vip(int argc, char **argv)
{
    struct vip_key vip;
    struct vip_config config;
    int map_fd;

    if (argc != 4)
        return -1;

    if (parse_vip_key(argv, &vip))
        return -1;

    if (parse_uint32(argv[3], &config.server_count) ||
        config.server_count == 0 ||
        config.server_count > MAX_SERVERS_PER_VIP) {
        fprintf(stderr, "invalid server count: %s\n", argv[3]);
        return -1;
    }

    map_fd = open_pinned_map(VIP_MAP_PATH);
    if (map_fd < 0)
        return -1;

    if (bpf_map_update_elem(map_fd, &vip, &config, BPF_ANY)) {
        fprintf(stderr, "failed to update vip_map: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    return 0;
}

static int del_vip(int argc, char **argv)
{
    struct vip_key vip;
    int map_fd;

    if (argc != 3)
        return -1;

    if (parse_vip_key(argv, &vip))
        return -1;

    map_fd = open_pinned_map(VIP_MAP_PATH);
    if (map_fd < 0)
        return -1;

    if (bpf_map_delete_elem(map_fd, &vip) && errno != ENOENT) {
        fprintf(stderr, "failed to delete VIP: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    return 0;
}

static int add_server(int argc, char **argv)
{
    struct server_key server_key = {0};
    struct server server = {0};
    int map_fd;

    if (argc != 6)
        return -1;

    if (parse_vip_key(argv, &server_key.vip))
        return -1;

    if (parse_uint32(argv[3], &server_key.slot) ||
        server_key.slot >= MAX_SERVERS_PER_VIP) {
        fprintf(stderr, "invalid server slot: %s\n", argv[3]);
        return -1;
    }

    if (inet_pton(AF_INET, argv[4], &server.address) != 1) {
        fprintf(stderr, "invalid server address: %s\n", argv[4]);
        return -1;
    }

    if (parse_mac_address(argv[5], server.mac_address)) {
        fprintf(stderr, "invalid server MAC: %s\n", argv[5]);
        return -1;
    }

    map_fd = open_pinned_map(SERVER_MAP_PATH);
    if (map_fd < 0)
        return -1;

    if (bpf_map_update_elem(map_fd, &server_key, &server, BPF_ANY)) {
        fprintf(stderr, "failed to update server_map: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    return 0;
}

static int del_server(int argc, char **argv)
{
    struct server_key server_key = {0};
    int map_fd;

    if (argc != 4)
        return -1;

    if (parse_vip_key(argv, &server_key.vip))
        return -1;

    if (parse_uint32(argv[3], &server_key.slot) ||
        server_key.slot >= MAX_SERVERS_PER_VIP) {
        fprintf(stderr, "invalid server slot: %s\n", argv[3]);
        return -1;
    }

    map_fd = open_pinned_map(SERVER_MAP_PATH);
    if (map_fd < 0)
        return -1;

    if (bpf_map_delete_elem(map_fd, &server_key) && errno != ENOENT) {
        fprintf(stderr, "failed to delete server: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    return 0;
}

static int set_tunnel_source(int argc, char **argv)
{
    struct tunnel_config config = {0};
    __u32 key = 0;
    int map_fd;

    if (argc != 1)
        return -1;

    if (inet_pton(AF_INET, argv[0], &config.source_address) != 1) {
        fprintf(stderr, "invalid tunnel source address: %s\n", argv[0]);
        return -1;
    }

    map_fd = open_pinned_map(TUNNEL_CONFIG_MAP_PATH);
    if (map_fd < 0)
        return -1;

    if (bpf_map_update_elem(map_fd, &key, &config, BPF_ANY)) {
        fprintf(stderr, "failed to update tunnel source: %s\n",
                strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    return 0;
}

int main(int argc, char **argv)
{
    int err = -1;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "add-vip"))
        err = add_vip(argc - 2, &argv[2]);
    else if (!strcmp(argv[1], "del-vip"))
        err = del_vip(argc - 2, &argv[2]);
    else if (!strcmp(argv[1], "add-b-server"))
        err = add_server(argc - 2, &argv[2]);
    else if (!strcmp(argv[1], "del-b-server"))
        err = del_server(argc - 2, &argv[2]);
    else if (!strcmp(argv[1], "set-tunnel-source"))
        err = set_tunnel_source(argc - 2, &argv[2]);
    if (err) {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
