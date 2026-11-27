//
//  ESBridge.h
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/7/22.
//

#ifndef ESBridge_h
#define ESBridge_h

#import <EndpointSecurity/EndpointSecurity.h>

/* The SIP flag Mac Monitor checks to decide whether Endpoint Security needs Full Disk Access
   (`SetupRequirements`), from XNU's `csr.h`. */
#define CSR_ALLOW_UNRESTRICTED_FS               (1 << 1)

typedef uint32_t csr_config_t;
extern int csr_get_active_config(csr_config_t *);
extern int csr_check(csr_config_t);

/// `es_muted_paths_events`: every path the client mutes, or `NULL` if Endpoint Security doesn't list them.
es_muted_paths_t* fetch_muted_paths(es_client_t* es_client);
/// `es_release_muted_paths`: frees what `fetch_muted_paths` returned.
void release_es_memory(es_muted_paths_t *muted_paths);

/// Connects to the kernel's network statistics control socket, `com.apple.network.statistics`, without blocking, and
/// asks for a receive buffer of `receive_buffer` bytes. `applied_buffer` gets the size the kernel gave. Returns the
/// socket, or `-errno`.
int nstat_connect(int receive_buffer, int *applied_buffer);
/// How many bytes are waiting on a socket (`FIONREAD`), or `-errno`.
int nstat_pending(int socket);

/* `proc_pidinfo`'s unique identifier flavor, from XNU's `proc_info.h`, which the SDK leaves out. */
#define MM_PROC_PIDUNIQIDENTIFIERINFO 17
struct mm_proc_uniqidentifierinfo {
    uint8_t p_uuid[16];
    uint64_t p_uniqueid;
    uint64_t p_puniqueid;
    int32_t p_idversion;
    uint32_t p_reserve2;
    uint64_t p_reserve3;
    uint64_t p_reserve4;
};

/* `csops_audittoken` and three of its operations, from XNU's `codesign.h`. The kernel checks the token's pid
   version, so a reused pid never answers for another process. */
#define MM_CS_OPS_STATUS 0
#define MM_CS_OPS_IDENTITY 11
#define MM_CS_OPS_TEAMID 14
extern int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);

#endif /* ESBridge_h */
