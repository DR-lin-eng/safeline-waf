#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static pid_t parse_pid(const char *value) {
    if (value == NULL || *value == '\0') {
        return -1;
    }

    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end && *end != '\0') {
        return -1;
    }
    if (parsed < 1 || parsed > 1 << 30) {
        return -1;
    }
    return (pid_t) parsed;
}

int main(int argc, char **argv) {
    pid_t pid = 1;
    if (argc > 1) {
        pid = parse_pid(argv[1]);
    }

    if (pid < 1) {
        fprintf(stderr, "invalid pid\n");
        return 2;
    }

    if (kill(pid, SIGHUP) != 0) {
        perror("kill");
        return 1;
    }

    return 0;
}
