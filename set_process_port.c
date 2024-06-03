#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>

#define ALLOWED_PORT_MAP "/sys/fs/bpf/allowed_port_map"
#define TARGET_PID_MAP "/sys/fs/bpf/target_pid_map"

pid_t get_pid_by_name(const char *name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep -x %s", name);
    FILE *cmd_fp = popen(cmd, "r");
    if (!cmd_fp) {
        perror("popen");
        return -1;
    }

    char pid_str[16];
    if (fgets(pid_str, sizeof(pid_str), cmd_fp) == NULL) {
        pclose(cmd_fp);
        return -1;
    }

    pclose(cmd_fp);
    return (pid_t)strtol(pid_str, NULL, 10);
}

int main(int argc, char **argv) {
    int port_map_fd, pid_map_fd;
    __u32 key = 0;
    __u16 port;
    __u32 pid;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <process_name> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *process_name = argv[1];
    port = (__u16)atoi(argv[2]);

    pid = get_pid_by_name(process_name);
    if (pid < 0) {
        fprintf(stderr, "Failed to get PID for process %s\n", process_name);
        return EXIT_FAILURE;
    }

    port_map_fd = bpf_obj_get(ALLOWED_PORT_MAP);
    if (port_map_fd < 0) {
        fprintf(stderr, "Failed to open BPF map for allowed port: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    pid_map_fd = bpf_obj_get(TARGET_PID_MAP);
    if (pid_map_fd < 0) {
        fprintf(stderr, "Failed to open BPF map for target PID: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (bpf_map_update_elem(port_map_fd, &key, &port, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update BPF map for allowed port: %s\n", strerror(errno));
        close(port_map_fd);
        close(pid_map_fd);
        return EXIT_FAILURE;
    }

    if (bpf_map_update_elem(pid_map_fd, &key, &pid, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update BPF map for target PID: %s\n", strerror(errno));
        close(port_map_fd);
        close(pid_map_fd);
        return EXIT_FAILURE;
    }

    printf("Successfully updated port to %d for process %s (PID %d)\n", port, process_name, pid);
    close(port_map_fd);
    close(pid_map_fd);
    return EXIT_SUCCESS;
}
