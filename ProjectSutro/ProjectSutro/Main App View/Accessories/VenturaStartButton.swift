//
//  VenturaStartButton.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/6/23.
//

import SwiftUI
import SutroESFramework

/// Mac Monitor "Start" button view with a custom SwiftUI sheet style alert.
@available(macOS, deprecated: 14, obsoleted: 14, message: "macOS 14 introduced a SwiftUI native way to do this with a confirmationDialog")
struct VenturaStartButton: View {
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
                .padding([.leading, .trailing], 5)
        }
        .buttonStyle(.borderedProminent)
        .disabled(recordingEvents || systemExtensionManager.connectionResult != .success)
        .help(systemExtensionManager.connectionResult == .success || recordingEvents ? ""
              : "Mac Monitor can't record yet. Settings ▸ Security Extension says what's missing.")
        .sheet(isPresented: $confirmClear) {
            VStack {
                AppIcon()
                Text("Clear system trace?")
                    .font(.headline)
                Text("Are you sure you want to clear all events?")
                
                VStack {
                    Button(action: {
                        clearSystemEventsUI()
                        confirmClear = false
                    }) {
                        Text("Confirm clear")
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    
                    Button(action: {
                        confirmClear = false
                    }) {
                        Text("Cancel")
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .tint(Color.secondary)
                    
                    
                }
                .padding(.top)
                
                Toggle("Don't ask again", isOn: Binding(
                    get: { !userPrefs.lifecycleWarnBeforeClear },
                    set: { userPrefs.lifecycleWarnBeforeClear = !$0 } ))
            }
            .padding()
            .cornerRadius(12)
            .shadow(radius: 20)
            .frame(width: 300)
            .background(Color(.windowBackgroundColor))
        }
    }
}
