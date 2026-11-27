//
//  ESBridge.c
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/7/22.
//

#include "ESBridge.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

es_muted_paths_t* fetch_muted_paths(es_client_t* es_client) {
    es_muted_paths_t *muted_paths = NULL;
    es_muted_paths_events(es_client, &muted_paths);
    return muted_paths;
}

void release_es_memory(es_muted_paths_t *muted_paths) {
    es_release_muted_paths(muted_paths);
}


int nstat_connect(int receive_buffer, int *applied_buffer) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        return -errno;
    }
    struct ctl_info info = {0};
    strlcpy(info.ctl_name, "com.apple.network.statistics", sizeof(info.ctl_name));
    struct sockaddr_ctl address = {.sc_len = sizeof(address), .sc_family = AF_SYSTEM, .ss_sysaddr = AF_SYS_CONTROL};
    int result = ioctl(fd, CTLIOCGINFO, &info);
    if (result == 0) {
        address.sc_id = info.ctl_id;
        result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    }
    if (result != 0 || fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != 0) {
        int failure = errno;
        close(fd);
        return -failure;
    }
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer));
    socklen_t length = sizeof(*applied_buffer);
    *applied_buffer = 0;
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, applied_buffer, &length);
    return fd;
}

int nstat_pending(int socket) {
    int waiting = 0;
    return ioctl(socket, FIONREAD, &waiting) == 0 ? waiting : -errno;
}
