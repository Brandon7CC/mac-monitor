//
//  SonomaStartButton.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/6/23.
//

import SwiftUI
import SutroESFramework

/// Mac Monitor "Start" button view with macOS 14 a `confirmationDialog`
@available(macOS, introduced: 14)
struct SonomaStartButton: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var agentTerminate: AgentCloseController
    @EnvironmentObject var userPrefs: UserPrefs
    /// Start closes an open trace.
    @EnvironmentObject var traceSession: TraceSession
    
    @Binding var recordingEvents: Bool
    @Binding var confirmClear: Bool
    
    /// Clear SystemEvents from the Core Data PSC and reset the UI
    ///
    /// The function will first stop a system trace (if one is occuring) we'll next clear the PSC using `clearSystemEvents()`
    public func clearSystemEventsUI() {
        var sentinel: Bool = false
        if recordingEvents {
            recordingEvents = false
            
            sentinel = true
        }
        
        systemExtensionManager.cleanup()
        systemExtensionManager.stopRecordingEvents()
        systemExtensionManager.coreDataContainer.clearSystemEvents()
        
        if sentinel {
            recordingEvents = true
            systemExtensionManager.startRecordingEvents()
            sentinel = false
        }
    }
    
    
    var body: some View {
        Button(action: {
            /// Recording replaces an open trace (its file is still on disk).
            if !traceSession.isLive { systemExtensionManager.coreDataContainer.clearSystemEvents() }
            recordingEvents = true
            systemExtensionManager.startRecordingEvents()
        }) {
            Text("Start")
                .bold()
                .buttonStyle(.automatic)
                .padding([.leading, .trailing], 5)
        }
        .disabled(recordingEvents || systemExtensionManager.connectionResult != .success)
        .onTapGesture {
            if !recordingEvents && systemExtensionManager.connectionResult != .success {
                agentTerminate.toggleQuitAlert()
            }
        }
        .alert(isPresented: $agentTerminate.showAlert) {
            Alert(
                title: Text("Quit and re-open!"),
                message: Text("You need to quit and re-open the app after completing **both** of these: Allow the System Extension and enable Full Disk Access."),
                primaryButton: .default(Text("Let's do it!")) {
                    let userDefaults = UserDefaults.standard
                    let defaultValues = ["lifecycleQuitInternal" : true]
                    userDefaults.register(defaults: defaultValues)
                    UserDefaults.standard.set(true, forKey: "lifecycleQuitInternal")
                    agentTerminate.quitAgent(esm: systemExtensionManager)
                },
                secondaryButton: .cancel()
            )
        }
        .confirmationDialog(
            "Are you sure you want to clear all events?",
            isPresented: $confirmClear
        ) {
            Button("Clear", role: .destructive) {
                clearSystemEventsUI()
                confirmClear = false
            }
            Button("Cancel", role: .cancel) {
                confirmClear = false
            }
        }
        .dialogSuppressionToggle(isSuppressed:
                                    Binding(
                                        get: { !userPrefs.lifecycleWarnBeforeClear },
                                        set: { userPrefs.lifecycleWarnBeforeClear = !$0 } )
        )
    }
}
