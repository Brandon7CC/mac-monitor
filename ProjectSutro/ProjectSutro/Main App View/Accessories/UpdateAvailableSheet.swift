//
//  UpdateAvailableSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/5/25.
//

import SwiftUI
import SutroESFramework

/// Offers an available update: its version, release date and notes, with Later and Install Now.
struct UpdateAvailableSheet: View {
    let updateDetails: UpdateDetails
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.dismiss) private var dismiss

    // MARK: - State for UI Feedback
    /// Controls the installation progress view.
    @State private var isInstalling: Bool = false
    /// Did the update fail to install? Shows the error alert.
    @State private var failed = false

    var body: some View {
        VStack(alignment: .leading) {
            // MARK: - Conditional Progress View
            if isInstalling {
                // Show a progress view and a message during installation.
                VStack {
                    ProgressView()
                    
                    Text("Installing \(updateDetails.version) update, please wait...")
                        .font(.title2)
                    
                    Text("Mac Monitor will reboot when the update is completed")
                }
                .multilineTextAlignment(.center)
            } else {
                HStack {
                    Image(systemName: "square.and.arrow.down.badge.checkmark")
                        .font(.largeTitle)
                        .foregroundColor(.accentColor)

                    Text("Update Available")
                        .font(.title)
                        .fontWeight(.bold)
                }
                .padding(.bottom)

                if let url = URL(string: ReleaseNotes.releasesPage.absoluteString + "/tag/\(updateDetails.version)") {
                    HStack {
                        Text("v\(ReleaseNotes.version) →")
                        Link(updateDetails.version, destination: url)
                    }
                    .font(.title3)
                    .bold()
                }

                Text("**Released:** `\(updateDetails.releaseDate)`")

                Text("Release Notes")
                    .font(.title3)
                    .bold()
                    .padding(.top)

                ScrollView {
                    Text(LocalizedStringKey(stringLiteral: updateDetails.releaseNotes))
                        .font(.body)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                }
                .frame(height: 200)
                .background(Color(NSColor.windowBackgroundColor))
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                )

                HStack {
                    Button(action: {
                        dismiss()
                    }) {
                        Text("Later")
                            .frame(maxWidth: .infinity)
                    }
                    .keyboardShortcut(.cancelAction)

                    Button(action: {
                        isInstalling = true
                        /// Called on the main thread.
                        systemExtensionManager.installUpdate { success in
                            guard success else {
                                isInstalling = false
                                failed = true
                                return
                            }
                            // 1. Schedule the relaunch for when this process exits.
                            systemExtensionManager.requestAgentRelaunch()

                            // 2. Dismiss the sheet to clean up the view hierarchy.
                            dismiss()

                            // 3. Terminate the app after a brief delay. Skip the "warn before quitting" prompt:
                            //    the relaunch only waits 10 seconds for this process to exit.
                            UserDefaults.standard.set(true, forKey: "lifecycleQuitInternal")
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                                NSApplication.shared.terminate(nil)
                            }
                        }
                    }) {
                        Text("Install Now")
                            .fontWeight(.semibold)
                            .frame(maxWidth: .infinity)
                    }
                    .keyboardShortcut(.defaultAction)
                }
                .frame(maxWidth: .infinity)
                .padding(.top)
            }
        }
        .padding(30)
        .frame(width: 500)
        .alert("Update Failed", isPresented: $failed) {
            Button("OK") { }
        } message: {
            Text("The update failed to install. Please check your network connection or try again later.")
        }
    }
}
