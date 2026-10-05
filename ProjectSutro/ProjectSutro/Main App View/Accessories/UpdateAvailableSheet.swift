//
//  UpdateAvailableSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/5/25.
//

import SwiftUI
import SutroESFramework
import OSLog

struct UpdateAvailableSheet: View {
    let updateDetails: UpdateDetails
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.dismiss) private var dismiss

    // MARK: - State for UI Feedback
    /// Controls the installation progress view.
    @State private var isInstalling: Bool = false
    /// Holds the error message if the update fails.
    @State private var errorMessage: String?
    /// Controls the presentation of the error alert.
    @State private var showUpdateErrorAlert: Bool = false

    var markdownText: LocalizedStringKey {
        LocalizedStringKey(stringLiteral: updateDetails.releaseNotes)
    }

    var currentAppVersion: String? {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
    }

    var updateTagURL: String {
        "https://github.com/Brandon7CC/mac-monitor/releases/tag/\(updateDetails.version)"
    }

    var body: some View {
        VStack(alignment: .leading) {
            // MARK: - Conditional Progress View
            if isInstalling {
                // Show a progress view and a message during installation.
                HStack {
                    VStack {
                        ProgressView()
                        
                        Text("Installing \(updateDetails.version) update, please wait...")
                            .font(.title2)
                        
                        Text("Mac Monitor will reboot when the update is completed")
                    }
                    .multilineTextAlignment(.center)
                }
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

                if let currentAppVersion = currentAppVersion,
                   let url = URL(string: updateTagURL) {
                    HStack {
                        Text("v\(currentAppVersion) →")
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
                    Text(markdownText)
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
                    .disabled(isInstalling)

                    Button(action: {
                        isInstalling = true
                        
                        Task {
                            let success = await withCheckedContinuation { continuation in
                                systemExtensionManager.installUpdate { success in
                                    continuation.resume(returning: success)
                                }
                            }

                            await MainActor.run {
                                if success {
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
                                } else {
                                    // Handle installation failure
                                    isInstalling = false
                                    errorMessage = "The update failed to install. Please check your network connection or try again later."
                                    showUpdateErrorAlert = true
                                }
                            }
                        }
                    }) {
                        Text("Install Now")
                            .fontWeight(.semibold)
                            .frame(maxWidth: .infinity)
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(isInstalling)
                }
                .frame(maxWidth: .infinity)
                .padding(.top)
            }
        }
        .padding(30)
        .frame(width: 500)
        .alert("Update Failed", isPresented: $showUpdateErrorAlert, presenting: errorMessage) { _ in
            Button("OK") { }
        } message: { message in
            Text(message)
        }
    }
}
