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
    @EnvironmentObject var userPrefs: UserPrefs
    /// Start closes an open trace.
    @EnvironmentObject var traceSession: TraceSession
    
    @Binding var recordingEvents: Bool
    @Binding var confirmClear: Bool
    
    /// Clear the events, recording again afterwards if Mac Monitor was recording.
    public func clearSystemEventsUI() {
        let wasRecording = recordingEvents
        systemExtensionManager.stopRecordingEvents()
        systemExtensionManager.coreDataContainer.clearSystemEvents()
        if wasRecording { systemExtensionManager.startRecordingEvents() }
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
        .help(systemExtensionManager.connectionResult == .success || recordingEvents ? ""
              : "Mac Monitor can't record yet. Settings ▸ Security Extension says what's missing.")
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
