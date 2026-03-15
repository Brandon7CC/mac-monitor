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
    @EnvironmentObject var agentTerminate: AgentCloseController
    @EnvironmentObject var userPrefs: UserPrefs
    
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
        systemExtensionManager.eventStore.clearEvents()
        
        if sentinel {
            recordingEvents = true
            systemExtensionManager.startRecordingEvents()
            sentinel = false
        }
    }
    
    
    var body: some View {
        Button(action: {
            recordingEvents = true
            systemExtensionManager.startRecordingEvents()
        }) {
            Text("Start")
                .bold()
                .padding([.leading, .trailing], 5)
        }
        .buttonStyle(.borderedProminent).disabled(recordingEvents || systemExtensionManager.connectionResult != .success).onTapGesture {
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
