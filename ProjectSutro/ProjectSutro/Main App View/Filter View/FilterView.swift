//
//  FilterView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 12/16/22.
//

import SwiftUI
import SutroESFramework
import OSLog


public struct Filters: Equatable {
    public var initiatingPaths: [String] = []
    public var targetPaths: [String] = []
    public var events: [String] = []
    public var userIDs: [String] = []
    
    public var rootIncludedInitiatingProcessPath: String?
    public var rootIncludedTargetProcessPath: String?
    public var shouldIncludeProcessSubTrees: Bool = false
    
    
    public func totalFilters() -> Int {
        var sum: Int = initiatingPaths.count + targetPaths.count + events.count + userIDs.count
        if rootIncludedInitiatingProcessPath != nil || rootIncludedTargetProcessPath != nil {
            sum += 1
        }
        
        return sum
    }
}


public func isEventFiltered(
    event: ESMessage,
    filteringLongRunningProcs: Bool = false,
    filterText: String,
    allFilters: Filters,
    systemExtensionManager: EndpointSecurityManager,
    initiatingLineageSet: Set<String>?,
    targetLineageSet: Set<String>?
) -> Bool {
    let inclusionFilterActive = allFilters.rootIncludedInitiatingProcessPath != nil ||
                                allFilters.rootIncludedTargetProcessPath != nil
    
    if inclusionFilterActive {
        var matchesAnInclusionFilter = false
        
        let initiatingToken = event.process.audit_token_string
        let initiatingPath = event.process.executable?.path
        
        // Check initiating process
        if let path = allFilters.rootIncludedInitiatingProcessPath {
            if allFilters.shouldIncludeProcessSubTrees {
                if initiatingLineageSet?.contains(initiatingToken) == true {
                    matchesAnInclusionFilter = true
                }
            } else if initiatingPath == path {
                matchesAnInclusionFilter = true
            }
        }
        
        if !matchesAnInclusionFilter, let path = allFilters.rootIncludedTargetProcessPath {
            if allFilters.shouldIncludeProcessSubTrees {
                if targetLineageSet?.contains(initiatingToken) == true {
                    matchesAnInclusionFilter = true
                }
            } else if initiatingPath == path {
                matchesAnInclusionFilter = true
            }
        }
        
        // Check exec target
        if !matchesAnInclusionFilter, let execEvent = event.event.exec {
            let targetToken = execEvent.target.audit_token_string
            let targetPath = execEvent.target.executable?.path
            
            if let path = allFilters.rootIncludedInitiatingProcessPath {
                if allFilters.shouldIncludeProcessSubTrees {
                    if initiatingLineageSet?.contains(targetToken) == true {
                        matchesAnInclusionFilter = true
                    }
                } else if targetPath == path {
                    matchesAnInclusionFilter = true
                }
            }
            
            if !matchesAnInclusionFilter, let path = allFilters.rootIncludedTargetProcessPath {
                if allFilters.shouldIncludeProcessSubTrees {
                    if targetLineageSet?.contains(targetToken) == true {
                        matchesAnInclusionFilter = true
                    }
                } else if targetPath == path {
                    matchesAnInclusionFilter = true
                }
            }
        }
        
        if !matchesAnInclusionFilter { return false }
    }
    
    // MARK: Non-lineage filters:
    if filteringLongRunningProcs,
       event.message_darwin_time.timeIntervalSince1970 < systemExtensionManager.clientConnectDT.timeIntervalSince1970 {
        return false
    }
    
    if allFilters.events.contains(event.es_event_type) { return false }
    if allFilters.userIDs.contains(event.process.euid_human ?? "") { return false }
    if allFilters.initiatingPaths.contains(event.process.executable?.path ?? "") { return false }
    
    let targetPath = event.target_path ?? ""
    if allFilters.targetPaths.contains(targetPath) ||
        !allFilters.targetPaths.filter({ targetPath.contains($0) }).isEmpty {
        return false
    }
    
    if !filterText.isEmpty,
       let target = event.context,
       !target.lowercased().contains(filterText) {
        return false
    }
    
    return true
}




struct FilterView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    @Binding var allFilters: Filters
    @Binding var filteredTelemetryShown: Bool
    @Binding var filterSelection: Set<String>
    @Binding var filteringLongRunningProcs: Bool
    @Binding var eventMaskEnabled: Bool
    @Binding var filterPlatform: Bool
    
    @State private var selectableEvents: [SelectableEvent] = getSupportedEventTypesSelectable()
    @State private var searchText: String = ""
    
    private var initiatingProcessPathFilters: [String] {
        allFilters.initiatingPaths
    }
    
    private var targetPathFilters: [String] {
        allFilters.targetPaths
    }
    
    private var eventFilters: Set<String> {
        return Set(allFilters.events.map { $0 })
    }
    
    private var eventFilterSearch: [String] {
        return Array(eventFilters).filter({
            if !searchText.isEmpty {
                return $0
                    .lowercased()
                    .contains(searchText.lowercased())
            }
            return true
        })
    }
    
    private var userIDs: [String] {
        allFilters.userIDs
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            ScrollView {
                Form {
                    // MARK: - Heading
                    Section {
                        Text("**Advanced**").font(.title2)
                        VStack(alignment: .leading) {
                            GroupBox {
                                HStack {
                                    if filterPlatform {
                                        Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow)
                                    }
                                    Image(systemName: "apple.logo")
                                    Text("**Drop platform binaries**: Enabling will *drop (not record)* *most* initiating events signed with an Apple certificate unless they target a non-platform process execute or fork event.")
                                    Spacer()
                                    Button(action: {
                                        filterPlatform.toggle()
                                        systemExtensionManager.togglePlatformBinaries()
                                    }) {
                                        Text(!filterPlatform ? "**Enable**" : "Disable")
                                    }.buttonStyle(.borderedProminent).tint(filterPlatform ? .pink : .green).opacity(0.8).padding(.trailing)
                                }
                            }
                        }
                    }
                    
                    Divider().padding(.top)
                    Section {
                        Text("**Artifact filtering**").font(.title2)
                        VStack(alignment: .leading) {
                            GroupBox {
                                Text("These objects have been filtered from view, but have not been dropped by Endpoint Security.").frame(maxWidth: .infinity, alignment: .leading)
                            }
                            
                            // MARK: Event mask
                            GroupBox {
                                HStack {
                                    if eventMaskEnabled {
                                        Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .yellow)
                                    }
                                    Image(systemName: "ellipsis.viewfinder")
                                    Text("**Event mask**: Enabling will filter, but not drop all events you are subscribed to from view. Use the \"Remove\" button to selectively view events.")
                                    Spacer()
                                    Button(action: {
                                        if !eventMaskEnabled {
                                            allFilters.events = getSupportedEventTypesSelectable().filter({
                                                systemExtensionManager.getSimpleEventSubscriptions().contains($0.eventString)
                                            }).map({$0.eventString})
                                        } else {
                                            allFilters.events.removeAll()
                                        }
                                        
                                        eventMaskEnabled.toggle()
                                    }) {
                                        Text(!eventMaskEnabled ? "**Enable**" : "Disable")
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .tint(eventMaskEnabled ? .pink : .green)
                                    .opacity(0.8)
                                    .padding(.trailing)
                                }
                            }
                        }
                    }
                    
                    
                    // MARK: - Path includes
                    if let procPath = allFilters.rootIncludedInitiatingProcessPath {
                        Divider()
                        Spacer(minLength: 10)
                        Section {
                            HStack {
                                Text("Include initiating process path")
                                    .font(.title2)
                                    .frame(alignment: .leading)
                                
                                if allFilters.shouldIncludeProcessSubTrees {
                                    Capsule()
                                        .fill(Color.green)
                                        .opacity(0.8)
                                        .overlay(
                                            Text("Including full tree")
                                                .bold()
                                        )
                                        .frame(maxWidth: 150)
                                }
                            }
                            
                            Spacer()
                            GroupBox {
                                VStack(alignment: .leading) {
                                    GroupBox {
                                        HStack {
                                            Text(procPath)
                                                .monospaced()
                                            Spacer()
                                            Button(action: {
                                                allFilters.rootIncludedInitiatingProcessPath = nil
                                                allFilters.shouldIncludeProcessSubTrees = false
                                            }) {
                                                Text("**Remove**")
                                            }
                                            .buttonStyle(.borderedProminent)
                                            .tint(.pink)
                                            .opacity(0.8)
                                            .padding(.trailing)
                                        }.frame(alignment: .leading)
                                    }
                                }.frame(maxWidth: .infinity, maxHeight: .infinity)
                            }
                        }
                    }
                    if let tgtProcPath = allFilters.rootIncludedTargetProcessPath {
                        Divider()
                        Spacer(minLength: 10)
                        Section {
                            HStack {
                                Text("Include target process path")
                                    .font(.title2)
                                    .frame(alignment: .leading)
                                
                                if allFilters.shouldIncludeProcessSubTrees {
                                    Capsule()
                                        .fill(Color.green)
                                        .opacity(0.8)
                                        .overlay(
                                            Text("Including full tree")
                                                .bold()
                                        )
                                        .frame(maxWidth: 150)
                                }
                            }
                            
                            Spacer()
                            GroupBox {
                                VStack(alignment: .leading) {
                                    GroupBox {
                                        HStack {
                                            Text(tgtProcPath)
                                                .monospaced()
                                            Spacer()
                                            Button(action: {
                                                allFilters.rootIncludedTargetProcessPath = nil
                                                allFilters.shouldIncludeProcessSubTrees = false
                                            }) {
                                                Text("**Remove**")
                                            }
                                            .buttonStyle(.borderedProminent)
                                            .tint(.pink)
                                            .opacity(0.8)
                                            .padding(.trailing)
                                        }.frame(alignment: .leading)
                                    }
                                }.frame(maxWidth: .infinity, maxHeight: .infinity)
                            }
                        }
                    }
                    
                    
                    
                    
                    Divider()
                    // MARK: - Initating process paths
                    if !initiatingProcessPathFilters.isEmpty {
                        Spacer(minLength: 10)
                        Section {
                            Text("Initiating process path").font(.title2).frame(alignment: .leading)
                            Spacer()
                            GroupBox {
                                VStack(alignment: .leading) {
                                    ForEach(Array(initiatingProcessPathFilters), id: \.self) { path in
                                        GroupBox {
                                            HStack {
                                                Text("`\(path)`")
                                                Spacer()
                                                Button(action: {
                                                    allFilters.initiatingPaths.removeAll(where: { $0 == path })
                                                }) {
                                                    Text("**Remove**")
                                                }.buttonStyle(.borderedProminent).tint(.pink).opacity(0.8).padding(.trailing)
                                            }.frame(alignment: .leading)
                                        }
                                    }
                                }.frame(maxWidth: .infinity, maxHeight: .infinity)
                            }
                        }
                        Divider()
                    }
                    
                    
                    // MARK: Target process paths
                    if !targetPathFilters.isEmpty {
                        Spacer(minLength: 10)
                        Section {
                            Text("Target process path").font(.title2).frame(alignment: .leading)
                            Spacer()
                            GroupBox {
                                VStack(alignment: .leading) {
                                    ForEach(targetPathFilters, id: \.self) { path in
                                        GroupBox {
                                            HStack {
                                                Text("`\(path)`")
                                                Spacer()
                                                Button(action: {
                                                    allFilters.targetPaths.removeAll(where: { $0 == path })
                                                }) {
                                                    Text("**Remove**")
                                                }.buttonStyle(.borderedProminent).tint(.pink).opacity(0.8).padding(.trailing)
                                            }.frame(alignment: .leading)
                                        }
                                    }
                                }.frame(maxWidth: .infinity, maxHeight: .infinity)
                            }
                        }
                        Divider()
                    }
                    
                    // MARK: - User IDs
                    if !userIDs.isEmpty {
                        Spacer(minLength: 10)
                        Section {
                            Text("User IDs").font(.title2).frame(alignment: .leading)
                            Spacer()
                            GroupBox {
                                VStack(alignment: .leading) {
                                    ForEach(Array(userIDs).sorted(), id: \.self) { user in
                                        GroupBox {
                                            HStack {
                                                Text("`\(user)`")
                                                Spacer()
                                                Button(action: {
                                                    allFilters.userIDs.removeAll(where: { $0 == user })
                                                }) {
                                                    Text("**Remove**")
                                                }.buttonStyle(.borderedProminent).tint(.pink).opacity(0.8).padding(.trailing)
                                            }.frame(alignment: .leading)
                                        }
                                    }
                                }.frame(maxWidth: .infinity, maxHeight: .infinity)
                            }
                        }
                        Divider()
                    }
                    
                    // MARK: - Endpoint Security events
                    if !eventFilters.isEmpty {
                        Spacer(minLength: 10)
                        Section {
                            Text("Endpoint Security events")
                                .font(.title2)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            
                            HStack {
                                TextField("", text: $searchText, prompt: Text("Search..."))
                                    .textFieldStyle(.roundedBorder)
                            }
                            
                            GroupBox {
                                VStack(alignment: .leading, spacing: 8) {
                                    ForEach(
                                        eventFilterSearch.sorted(),
                                        id: \.self
                                    ) { event in
                                        GroupBox {
                                            HStack {
                                                Image(systemName: eventStringToImage(from: event))
                                                Text(event)
                                                    .font(.system(.body, design: .monospaced))
                                                    .fontWeight(.semibold)
                                                Spacer()
                                                Button("Remove") {
                                                    allFilters.events.removeAll(where: { $0 == event })
                                                }
                                                .buttonStyle(.borderedProminent)
                                                .tint(.pink)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Divider()
                    }
                    
                }.padding(.all)
            }
        }
        .frame(minWidth: 800, minHeight: 600, maxHeight: 800)
        .onAppear {
            systemExtensionManager.requestEventSubscriptions()
        }
        Button("Close", action: {
            filteredTelemetryShown.toggle()
        }).buttonStyle(.borderedProminent).tint(.pink).frame(alignment: .center).padding(.all)
    }
}

