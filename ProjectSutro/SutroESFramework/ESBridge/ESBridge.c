//
//  ESBridge.c
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/7/22.
//

#include "ESBridge.h"

es_muted_paths_t* fetch_muted_paths(es_client_t* es_client) {
    es_muted_paths_t *muted_paths = NULL;
    es_muted_paths_events(es_client, &muted_paths);
    return muted_paths;
}

void release_es_memory(es_muted_paths_t *muted_paths) {
    es_release_muted_paths(muted_paths);
}
