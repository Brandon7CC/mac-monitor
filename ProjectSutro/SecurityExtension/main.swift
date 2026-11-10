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


/// The one saved mute set, shared by Mac Monitor's capture and every `macmonitor` stream.
let savedMutes = SavedMuteSet()

/// Who may use `macmonitor` without `sudo`: Settings > Command Line. Only root by default.
let commandLineAccess = CommandLineAccessStore()

/// The Mac's one indicator set, kept by root: Mac Monitor's capture and every `macmonitor` stream stamp each event
/// with those it matches.
let savedIndicators = SavedIndicatorSet()

/// Mac Monitor's side: the app's event stream, its subscriptions and its saved sets.
let sensorService = SensorService(savedMutes: savedMutes, savedIndicators: savedIndicators,
                                  commandLineAccess: commandLineAccess, updates: UpdateInstaller())

/// Lives for the life of the process: `NSXPCListener` only holds its delegate weakly. `macmonitor status` asks the
/// command line's side, which asks Mac Monitor's who is connected.
let sensorListener = SensorListener(
    app: sensorService,
    commandLine: StreamService(savedMutes: savedMutes, savedIndicators: savedIndicators, access: commandLineAccess,
                               appCapture: sensorService.captureState))

autoreleasepool {
    os_log("🏎 Hello from the Mac Monitor Security Extension!")
    
    /// Before any request: the first run creates the saved sets from Mac Monitor's own. Loading the indicators
    /// compiles the shipped ones first, and logs a fault for any that can't run.
    savedMutes.load()
    savedIndicators.load()
    // Settings > Command Line's authorization right
    CommandLineToolAuthorization.registerRight()
    // Let's get this show on the road!
    sensorListener.activate()
}

dispatchMain()
