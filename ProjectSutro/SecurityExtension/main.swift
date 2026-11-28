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


/// Started to compile Apple's XProtect rules for the scanner: compile them as `nobody` and exit, before anything else
/// runs (``XProtectRuleCompiler``).
if let status = XProtectRuleCompiler.runIfAsked(CommandLine.arguments) { exit(status) }

/// The one saved mute set, shared by Mac Monitor's capture and every `macmonitor` stream.
let savedMutes = SavedMuteSet()

/// Who may use `macmonitor` without `sudo`: Settings > Command Line. Only root by default.
let commandLineAccess = CommandLineAccessStore()

/// Settings > General's enrichment switches, Mac-wide: on until Mac Monitor turns one off.
let enrichmentSwitches = EnrichmentSwitchStore()

/// The Mac's one indicator set, kept by root: Mac Monitor's capture and every `macmonitor` stream stamp each event
/// with those it matches.
///
/// Not in 3.2: looking on GitHub for a newer indicator pack (`SavedIndicatorSet+Updates.swift`). The work is done
/// and tested, and waits for a later release. Passing the fetcher turns it on.
let savedIndicators = SavedIndicatorSet(/* fetcher: IndicatorPackFetcher() */)

/// Looks up Mac Monitor's releases for Mac Monitor and `macmonitor`, and installs one for Mac Monitor.
let updates = UpdateInstaller()
/// Mac Monitor's side: the app's event stream, its subscriptions and its saved sets.
let sensorService = SensorService(savedMutes: savedMutes, savedIndicators: savedIndicators,
                                  commandLineAccess: commandLineAccess, switches: enrichmentSwitches,
                                  updates: updates)

/// Lives for the life of the process: `NSXPCListener` only holds its delegate weakly. `macmonitor status` asks the
/// command line's side, which asks Mac Monitor's who is connected.
let sensorListener = SensorListener(
    app: sensorService,
    commandLine: StreamService(savedMutes: savedMutes, savedIndicators: savedIndicators, access: commandLineAccess,
                               appCapture: sensorService.captureState, updates: updates))

autoreleasepool {
    os_log("🏎 Hello from the Mac Monitor Security Extension!")
    
    /// Before any request: the first run creates the saved sets from Mac Monitor's own. Loading the indicators
    /// compiles the shipped ones first, and logs a fault for any that can't run.
    savedMutes.load()
    savedIndicators.load()
    /// Look for a newer indicator pack once a day, unless the mode is off.
    savedIndicators.startUpdates()
    // Settings > Command Line's authorization right
    CommandLineToolAuthorization.registerRight()
    // Let's get this show on the road!
    sensorListener.activate()
}

dispatchMain()
