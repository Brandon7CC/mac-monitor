//
//  main.swift
//  SecurityExtension
//
//  Created by Brandon Dalton on 7/5/22.
//

import Foundation
import EndpointSecurity
import OSLog
import SutroESFramework


autoreleasepool {
    os_log("🏎 Hello from the Mac Monitor Security Extension!")
    
    // Let's get this show on the road!
    let esManager: EndpointSecurityManager = EndpointSecurityManager()
    RCXPCConnection.rcXPCConnection.startXPCListener(esManager: esManager)
}

dispatchMain()
