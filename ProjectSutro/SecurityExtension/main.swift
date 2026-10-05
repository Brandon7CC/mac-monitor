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
import CoreData


/// Lives for the life of the process: `NSXPCListener` only holds its delegate weakly.
let sensorService: SensorService = SensorService()

autoreleasepool {
    os_log("🏎 Hello from the Mac Monitor Security Extension!")
    
    // Let's get this show on the road!
    sensorService.activate()
}

dispatchMain()
