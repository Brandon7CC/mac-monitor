//
//  ProjectSutroApp.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 7/5/22.
//

import SwiftUI
import SutroESFramework
import OSLog

/// Mac Monitor: *Project Sutro*
///
///
/// Author: Brandon Dalton
///
@main
struct ProjectSutroApp: App {
    /// ``TerminationDelegate`` handles responding to ``applicationShouldTerminate``.
    ///
    /// This way we can give users the option to confirm before quitting
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    /// Open a new "Event metadata" window
    @Environment(\.openWindow) private var openEventJSON
    
    /// Track everything going on with System Events and the Security Extension
    @StateObject var systemExtensionManager: EndpointSecurityManager = EndpointSecurityManager()
    /// Track all filters offered by Mac Monitor
    @State private var allFilters: Filters = Filters()
    /// Load user preferences from ``UserDefaults``
    @State var userPrefs: UserPrefs = UserPrefs()
    
    /// Is a system trace occuring?
    @State private var recordingEvents: Bool = false
    /// Should the "System Security Unified" table be shown?
    @State var unifiedViewSelected: Bool = true
    /// Should the "Process Execution" table be shown?
    @State var processExecSelected: Bool = true
    /// Should the SwiftUI mini-chart be shown
    @State var viewMiniChart: Bool = true
    
    /// The currently selected System Event (i.e. table row)
    @State private var eventSelection = Set<ESMessage.ID>()
    /// Enables users to right click and mute path events
    @State var pathToMute: String = ""
    /// The text to filter by in the context search field
    @State private var filterText: String = ""
    /// Is the event mask enabled?
    @State private var eventMaskEnabled: Bool = false
    /// Are we filtering long processes which executed before Mac Monitor was started?
    @State private var filteringLongRunningProcs: Bool = false
    
    @AppStorage("forcedDarkMode") private var forcedDarkMode = false
    
    // MARK: - Update Check State
    /// Holds the details of an available update. If nil, it means no update is available or the check hasn't run.
    @State private var updateToShow: UpdateDetails?
    /// Controls presentation for the "No Update Found" alert.
    @State private var showNoUpdateAlert: Bool = false
    /// Used to disable the update button while a check is in progress.
    @State private var isCheckingForUpdate: Bool = false
    
    /// Dynamically query the Security Extension to get the globally muted paths at the Endpoint Security level
    var globallyMutedPaths: Set<String> { systemExtensionManager.globallyMutedPaths }
    
    @AppStorage("lifecycleWarnBeforeQuit") var shouldWarnBeforeAppQuit: Bool = false
    
    init() {
        /// Secondary entry-point for handling Security Extension deactivation ``--deactivate-security-extension``
        if CommandLine.arguments.contains("--deactivate-security-extension") {
            print("[Mac Monitor]\tSubmitting deactivation request to the system. User interaction IS required.")
            systemExtensionManager.uninstallSystemExtension()
        }
    }
    
    var body: some Scene {
        WindowGroup {
            VStack(alignment: .leading) {
                EventView(
                    recordingEvents: $recordingEvents,
                    unifiedViewSelected: $unifiedViewSelected,
                    processExecSelected: $processExecSelected,
                    viewMiniChart: $viewMiniChart,
                    filteringLongRunningProcs: $filteringLongRunningProcs,
                    eventSelection: $eventSelection,
                    filterText: $filterText,
                    allFilters: $allFilters,
                    eventMaskEnabled: $eventMaskEnabled
                )
                .environmentObject(systemExtensionManager)
                .environmentObject(userPrefs)
                .padding(.bottom)
                .frame(minWidth: 1200, minHeight: 750)
            }
            .preferredColorScheme(userPrefs.forcedDarkMode ? .dark : nil)
            .onAppear {
                UserDefaults.standard.set(false, forKey: "lifecycleQuitInternal")
                
                /// If auto-updates are enabled then check at app launch
                if userPrefs.autoUpdates {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                        systemExtensionManager.checkForUpdates { details in
                            if let details = details {
                                updateToShow = details
                            }
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding()
            .sheet(item: $updateToShow) { details in
                UpdateAvailableSheet(updateDetails: details)
                    .environmentObject(systemExtensionManager)
            }
            .alert("✅ Up-to-date!", isPresented: $showNoUpdateAlert) {
                Button("Ok") { }
            } message: {
                Text("You're on the latest version of Mac Monitor!")
            }
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Mac Monitor") {
                    NSApplication.shared.orderFrontStandardAboutPanel(
                        options: [
                            .credits: NSAttributedString(
                                string: "Build name: \(Bundle.main.infoDictionary?["ProjectSutroBuildName"] as? String ?? "Unknown")",
                                attributes: [.font: NSFont.boldSystemFont(ofSize: NSFont.smallSystemFontSize)]
                            ),
                            .init(rawValue: "Copyright"): "2025 Brandon Dalton"
                        ]
                    )
                }
                
                Toggle("Warn before quitting?", isOn: $shouldWarnBeforeAppQuit)
                
                Toggle("Force dark mode", isOn: $forcedDarkMode)
                
                Divider()
                
                Button("Check for Updates") {
                    isCheckingForUpdate = true
                    systemExtensionManager.checkForUpdates { details in
                        isCheckingForUpdate = false
                        if let details = details {
                            updateToShow = details
                        } else {
                            showNoUpdateAlert = true
                        }
                    }
                }
                .disabled(isCheckingForUpdate)
            }
            
            CommandGroup(replacing: .help) {
                Section("GitHub") {
                    Button("Bug report form") {
                        NSWorkspace.shared.open(URL(string: "https://github.com/brandon7cc/mac-monitor/issues/new?assignees=Brandon7CC&labels=bug&template=bug_report.md&title=")!)
                    }
                    Button("Feature request form") {
                        NSWorkspace.shared.open(URL(string: "https://github.com/brandon7cc/mac-monitor/issues/new?assignees=Brandon7CC&labels=enhancement&template=feature_request.md&title=")!)
                    }
                }
                
                Section("Want more?") {
                    Button("Email me: `brandon@swiftlydetecting.com`") {
                        NSWorkspace.shared.open(URL(string: "mailto:brandon@swiftlydetecting.com")!)
                    }
                }
            }
            
            CommandGroup(replacing: .sidebar) {
                Text("Table views")
                Toggle(sources: [$processExecSelected, $viewMiniChart], isOn: \.self) {
                    Label("Process execute", systemImage: "checkmark.seal")
                }.disabled(!unifiedViewSelected).keyboardShortcut("1")
                
                Toggle("Unified Endpoint Security", isOn: $unifiedViewSelected)
                    .disabled(!processExecSelected).keyboardShortcut("2")
                
                Divider()
                
                Toggle(sources: [$unifiedViewSelected, $processExecSelected, $viewMiniChart], isOn: \.self) {
                    Label("Default", systemImage: "checkmark.seal")
                }.keyboardShortcut("0")
            }
            
            CommandMenu("Security Extension") {
                Button("System Setting: Full Disk Access") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
                }
                
                Divider()
                
                Button {
                    systemExtensionManager.activateSystemExtension()
                } label: {
                    Label("Install Security Extension", systemImage: "arrow.down.doc.fill")
                }
                
                Button {
                    systemExtensionManager.uninstallSystemExtension()
                } label: {
                    Label("Uninstall Security Extension", systemImage: "arrow.up.doc.fill")
                }
            }
            
            #if DEBUG
            CommandMenu("Debug") {
                Button("Capture Event Fixture...") {
                    FixtureCapture.captureWithSavePanel()
                }
            }
            #endif
            
            CommandMenu("Export telemetry") {
                Section("JSON (pretty)") {
                    Button("Full system trace") {
                        recordingEvents = false
                        systemExtensionManager.stopRecordingEvents()
                        systemExtensionManager.eventStore.exportFullTrace()
                    }
                    
                    Button("Selected events \(eventSelection.count > 0 ? ": \(eventSelection.count)" : "")") {
                        recordingEvents = false
                        systemExtensionManager.stopRecordingEvents()
                        
                        systemExtensionManager.eventStore
                            .exportSelectedEvents(
                                eventIDs: Array(eventSelection)
                            )
                        
                        
                    }.disabled(eventSelection.isEmpty)
                }
                
                Divider()
                
                Section("JSONL (lines)") {
                    Button("Full system trace") {
                        recordingEvents = false
                        systemExtensionManager.stopRecordingEvents()
                        systemExtensionManager.eventStore.exportFullTrace(jsonl: true)
                    }
                    .keyboardShortcut("s", modifiers: .command)
                    
                    Button("Selected events \(eventSelection.count > 0 ? ": \(eventSelection.count)" : "")") {
                        recordingEvents = false
                        systemExtensionManager.stopRecordingEvents()
                        systemExtensionManager.eventStore.exportSelectedEvents(eventIDs: Array(eventSelection), jsonl: true)
                    }
                    .keyboardShortcut("s", modifiers: [.command, .shift])
                    .disabled(eventSelection.isEmpty)
                }
            }
        }
        
        Settings {
            AgentSettingsView(pathToMute: $pathToMute, allFilters: $allFilters, eventMaskEnabled: $eventMaskEnabled)
                .environmentObject(systemExtensionManager)
                .environmentObject(userPrefs)
                .preferredColorScheme(userPrefs.forcedDarkMode ? .dark : nil)
        }
        
        WindowGroup("Event Facts", for: ESMessage.ID.self) { $eventID in
            if let id = eventID {
                AppWrapperForFacts(id: id, allFilters: $allFilters)
                    .environmentObject(systemExtensionManager)
                    .environmentObject(userPrefs)
                    .frame(minWidth: 700, minHeight: 400)
                
            }
        }
        .defaultPosition(.topLeading).defaultSize(width: 1000, height: 900)
    }
}
