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


/// The one saved mute set, shared by Mac Monitor's capture and every `macmonitor` stream.
let savedMutes = SavedMuteSet()

/// Lives for the life of the process: `NSXPCListener` only holds its delegate weakly.
let sensorListener = SensorListener(app: SensorService(savedMutes: savedMutes),
                                    commandLine: StreamService(savedMutes: savedMutes))

autoreleasepool {
    os_log("🏎 Hello from the Mac Monitor Security Extension!")
    
    /// Before any request: the first run creates the saved set from Mac Monitor's default set.
    savedMutes.load()
    /// The right an administrator approves to change /usr/local/bin/macmonitor
    CommandLineToolAuthorization.registerRight()
    // Let's get this show on the road!
    sensorListener.activate()
}

dispatchMain()
