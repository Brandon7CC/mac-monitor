//
//  ESBridge.h
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/7/22.
//

#ifndef ESBridge_h
#define ESBridge_h

#import <EndpointSecurity/EndpointSecurity.h>

/* The SIP flag the Security Extension checks, from XNU's `csr.h`. */
#define CSR_ALLOW_UNRESTRICTED_FS               (1 << 1)

typedef uint32_t csr_config_t;
extern int csr_get_active_config(csr_config_t *);
extern int csr_check(csr_config_t);

/// `es_muted_paths_events`: every path the client mutes, or `NULL` if Endpoint Security doesn't list them.
es_muted_paths_t* fetch_muted_paths(es_client_t* es_client);
/// `es_release_muted_paths`: frees what `fetch_muted_paths` returned.
void release_es_memory(es_muted_paths_t *muted_paths);

#endif /* ESBridge_h */
