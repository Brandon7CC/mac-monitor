//
//  PathMutingSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import SutroESFramework


/// One saved mute: its type, its path, and a button that removes it from the saved set.
struct PathUnmuteView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    var mutedPath: ESMutedPath

    var body: some View {
        HStack {
            MuteTypeBadgeView(path: mutedPath)

            Text("`\(mutedPath.path)`")
            
            Spacer()
            
            Button(action: {
                /// No events removes the path, whatever it's muted for.
                systemExtensionManager.puntPathToUnmute(pathToUnmute: mutedPath.path, type: mutedPath.type, events: [])
            }) {
                Text("**Unmute**")
            }
            .buttonStyle(.borderedProminent)
            .tint(.pink)
            .opacity(0.8)
            .padding(.trailing)
            .disabled(!systemExtensionManager.canChangeSavedMutes)
        }
    }
}

/// The saved mute set, one box per path, each opening the events it's muted for.
struct MutedPathsScrollView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    var mutedPaths: [ESMutedPath]
    @State private var pathSelected: ESMutedPath? = nil
    
    var body: some View {
        Group {
            if !mutedPaths.isEmpty {
                ScrollView {
                    ForEach(mutedPaths) { mutedPath in
                        GroupBox {
                            VStack(alignment: .leading) {
                                PathUnmuteView(mutedPath: mutedPath)
                                    .environmentObject(systemExtensionManager)
                                
                                Button(mutedPath.events.isEmpty ? "**All events**"
                                       : "Targeted events **(\(mutedPath.eventCount))**") {
                                    self.pathSelected = mutedPath
                                }
                            }
                        }
                    }
                }
                .frame(alignment: .leading)
                .textSelection(.enabled)
            } else {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow)
                    Text("The saved mute set is empty! Expect high event volume / noise to signal ratio!").font(.title3)
                }
            }
        }
        .sheet(item: $pathSelected) { selectedPath in
            TargetedEventsView(path: selectedPath)
                .environmentObject(systemExtensionManager)
                .frame(
                    minWidth: 600,
                    maxWidth: 600,
                    minHeight: 600,
                    maxHeight: 600
                )
        }
    }
}


/// The search scope for the muted paths view.
/// We can search across the path muted, the muting type (``es_mute_path_type_t``), and the events muted.
enum SearchType: String, CaseIterable, Identifiable {
    case path, muteType, events
    
    var id: Self { self }
}

/// The muting type (``es_mute_path_type_t``) to search against.
enum MuteType: String, CaseIterable, Identifiable {
    case ES_MUTE_PATH_TYPE_PREFIX
    case ES_MUTE_PATH_TYPE_LITERAL
    case ES_MUTE_PATH_TYPE_TARGET_PREFIX
    case ES_MUTE_PATH_TYPE_TARGET_LITERAL
    
    var id: Self { self }
}


/// Settings ▸ Path Muting: the saved mute set the Security Extension keeps, with search, Import, Export, Add, Unmute
/// all, and Reset to Default.
struct ESMutingTabView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @State private var selectedPath = Set<String>()
    
    @State private var showPathMuteAddSheet: Bool = false
    @State private var unmuteAllAlert: Bool = false
    @State private var resetAlert: Bool = false
    
    @State private var searchText: String = ""
    @State private var searchTypeScope: SearchType = .path
    @State private var muteType: MuteType = .ES_MUTE_PATH_TYPE_LITERAL
    
    // MARK: Path muting settingss
    @Binding var pathToMute: String
    
    var mutedPaths: [ESMutedPath] {
        let filteredPaths = systemExtensionManager.simpleGetMutedPaths().filter { obj in
            if !searchText.isEmpty || searchTypeScope == .muteType {
                switch searchTypeScope {
                case .path:
                    return obj.path.lowercased().contains(searchText.lowercased())
                /// The `muteType` here is one of ``es_mute_path_type_t``
                case .muteType:
                    return obj.type == muteType.rawValue
                case .events:
                    return obj.events.contains { $0.lowercased().contains(searchText.lowercased()) }
                }
            }
            return true
        }

        return filteredPaths.sorted { lhs, rhs in
            if lhs.type != rhs.type {
                // Primary sort: by mute type.
                return lhs.type < rhs.type
            }
            
            if lhs.path.count != rhs.path.count {
                // Secondary sort: by path length, shortest first.
                return lhs.path.count < rhs.path.count
            }
            
            // Tertiary sort: by path, alphabetically.
            return lhs.path < rhs.path
        }
    }
    
    /// Can this Mac Monitor change the saved set? One refused the event stream, or a standard user's, may only read it.
    private var canEdit: Bool { systemExtensionManager.canChangeSavedMutes }
    
    /// Shows what the Security Extension refused or left out of the last mute request.
    private var showsProblems: Binding<Bool> {
        Binding(get: { !systemExtensionManager.muteProblems.isEmpty },
                set: { if !$0 { systemExtensionManager.muteProblems = [] } })
    }
    
    var body: some View {
        Form {
            VStack {
                Section {
                    VStack(alignment: .leading) {
                        GroupBox {
                            VStack(alignment: .leading) {
                                Label("**Unified path muting**", systemImage: "globe").font(.title3)
                                Divider()
                                Text("""
                                    Paths added here will cause events matching the initiating executable image or \
                                    target path to be muted at the endpoint security level. Additionally, paths can be \
                                    muted only for some events. Muting is a powerful feature at the ES level that will \
                                    help improve performance during heavy traces.
                                    """)
                                .font(.callout)
                                Text("""
                                    The Security Extension keeps this saved mute set: it survives restarts, it's \
                                    shared with `sudo macmonitor`, and it doesn't include Endpoint Security's own \
                                    default mutes (Export ▸ Apple mute set…).
                                    """)
                                .font(.callout).foregroundStyle(.secondary)
                            }
                        }
                        
                        if let notice = systemExtensionManager.muteNotice {
                            GroupBox {
                                Label(notice, systemImage: "exclamationmark.triangle.fill")
                                    .symbolRenderingMode(.multicolor)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        
                        /// A standard user's Mac Monitor may only read the saved set: say why its controls are off.
                        if systemExtensionManager.savedMutesNeedAdministrator,
                           let reason = MuteAccess.standardUser.refusal?.problem {
                            GroupBox {
                                Label(reason, systemImage: "lock.fill")
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        
                        HStack {
                            Picker("Field", selection: $searchTypeScope) {
                                Text("Path").tag(SearchType.path)
                                Text("Mute type").tag(SearchType.muteType)
                                Text("Events").tag(SearchType.events)
                            }
                            .frame(minWidth: 150, maxWidth: 150)
                            
                            if searchTypeScope == .muteType {
                                Picker("Mute type", selection: $muteType) {
                                    Text("ES_MUTE_PATH_TYPE_PREFIX")
                                        .tag(MuteType.ES_MUTE_PATH_TYPE_PREFIX)
                                    Text("ES_MUTE_PATH_TYPE_LITERAL")
                                        .tag(MuteType.ES_MUTE_PATH_TYPE_LITERAL)
                                    Text("ES_MUTE_PATH_TYPE_TARGET_PREFIX")
                                        .tag(
                                            MuteType.ES_MUTE_PATH_TYPE_TARGET_PREFIX
                                        )
                                    Text("ES_MUTE_PATH_TYPE_TARGET_LITERAL")
                                        .tag(
                                            MuteType.ES_MUTE_PATH_TYPE_TARGET_LITERAL
                                        )
                                }
                                .frame(maxWidth: .infinity)
                            } else {
                                TextField("**Search**", text: $searchText)
                                    .frame(maxWidth: .infinity)
                            }
                            
                            MuteFileMenu()
                                .environmentObject(systemExtensionManager)
                        }
                        
                        Divider()
                        
                        MutedPathsScrollView(mutedPaths: mutedPaths)
                            .environmentObject(systemExtensionManager)
                    }
                }
                .sheet(isPresented: $showPathMuteAddSheet) {
                    MuteAddSheet(showPathMuteAddSheet: $showPathMuteAddSheet, pathToMute: $pathToMute).frame(minWidth: 650, maxWidth: 650, minHeight: 500).padding(.all)
                }
                Divider()
                HStack {
                    Button("**Add path to mute**") {
                        withAnimation {
                            showPathMuteAddSheet.toggle()
                        }
                    }
                    .disabled(!canEdit)
                    
                    Button(action: {
                        unmuteAllAlert.toggle()
                    }) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .symbolRenderingMode(.palette)
                                .foregroundStyle(.black, .yellow)
                            Text("Unmute all paths")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.pink)
                    .opacity(0.8)
                    .alert("Path mute warning!", isPresented: $unmuteAllAlert, actions: {
                        Button("Changed my mind!", role: .cancel, action: {})
                        Button("Continue", role: .destructive, action: {
                            // MARK: Step #1 in unmuting paths
                            systemExtensionManager.unmuteAllPaths()
                        })
                    }, message: {
                        Text("""
                            Are you sure you want to unmute all paths? This empties the saved mute set and will \
                            dramatically increase event count.
                            """)
                    })
                    .disabled(systemExtensionManager.simpleGetMutedPaths().isEmpty || !canEdit)
                    
                    Button("Reset to Default") {
                        resetAlert.toggle()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                    .opacity(0.8)
                    .disabled(!canEdit)
                    .help("Replace the saved mute set with Mac Monitor's default set.")
                    .alert("Reset the saved mute set?", isPresented: $resetAlert, actions: {
                        Button("Cancel", role: .cancel, action: {})
                        Button("Reset to Default", role: .destructive, action: {
                            systemExtensionManager.resetMuteSetToDefault()
                        })
                    }, message: {
                        Text("""
                            Replace the saved mute set (\(systemExtensionManager.simpleGetMutedPaths().count) mutes) \
                            with Mac Monitor's default set (\(MuteList.shippedDefault.count))? This applies right away \
                            to Mac Monitor and to every `macmonitor stream` that follows the saved set.
                            """)
                    })
                }
            }
        }
        .alert("Saved mute set", isPresented: showsProblems, actions: {
            Button("OK", role: .cancel, action: {})
        }, message: {
            Text(MuteFileMenu.summary(of: systemExtensionManager.muteProblems))
        })
        .onAppear {
            systemExtensionManager.requestMutedPaths()
        }
        /// Pick up changes `sudo macmonitor` made while the window was in the background.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            systemExtensionManager.requestMutedPaths()
        }
    }
}
