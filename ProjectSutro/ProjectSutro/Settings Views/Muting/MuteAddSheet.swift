//
//  MuteAddSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework


/// How the Add sheet matches the path it mutes.
enum MuteMode: String, CaseIterable, Identifiable {
    case globalPathPrefix, globalPathLiteral, targetPathPrefix, targetPathLiteral, processAuditToken
    var id: Self { self }
}


/// Adds a path to the saved mute set, for every event or only the selected ones.
struct MuteAddSheet: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Binding var showPathMuteAddSheet: Bool
    
    // MARK: Path muting settingss
    @State private var selectedMuteMode: MuteMode = .globalPathPrefix
    @Binding var pathToMute: String
    @State private var muteType: String = ""
    @State var eventToggle: Bool = true
    
    @State private var selectableEvents: [SelectableEvent] = getAllEventTypesSelectable()
    private var eventSubscriptions: [String] { systemExtensionManager.getSimpleEventSubscriptions() }
    
    private var typeMuteMode: es_mute_path_type_t {
        switch(selectedMuteMode) {
        case .globalPathPrefix:
            return ES_MUTE_PATH_TYPE_PREFIX
        case .globalPathLiteral:
            return ES_MUTE_PATH_TYPE_LITERAL
        case .targetPathPrefix:
            return ES_MUTE_PATH_TYPE_TARGET_PREFIX
        case .targetPathLiteral:
            return ES_MUTE_PATH_TYPE_TARGET_LITERAL
        default:
            return ES_MUTE_PATH_TYPE_TARGET_LITERAL
        }
    }
    
    var body: some View {
        Form {
            Section {
                Text("**Path mute properties**").font(.title3)
                GroupBox {
                    HStack {
                        Image(systemName: "info.square")
                        Text("To mute a executable path for all ES events click \"Mute path\". To mute a path only for the selected events click \"Mute path events\"").font(.callout).padding(.trailing)
                    }
                }
                Spacer(minLength: 10.0)
                TextField("Binary target path", text: $pathToMute)
                Picker("Mute by", selection: $selectedMuteMode) {
                    Text("Initiating executable path prefix").tag(MuteMode.globalPathPrefix)
                    Text("Initiating executable path literal").tag(MuteMode.globalPathLiteral)
                    Text("Target path prefix").tag(MuteMode.targetPathPrefix)
                    Text("Target path literal").tag(MuteMode.targetPathLiteral)
                }
            }
            Divider()
            Section("**Endpoint Security client properties**") {
                GroupBox {
                    Text("The matching executable image path will only be muted for these events ES events. Please note `AUTH` events have no effect in this context. **First** subscribe to the events you're interested in.").frame(maxWidth: .infinity).padding(.trailing)
                }
                
                List {
                    ForEach(selectableEvents.lazy.filter({
                        if eventSubscriptions.contains($0.eventString) {
                            if selectedMuteMode == .globalPathLiteral || selectedMuteMode == .globalPathPrefix {
                                return true
                            } else {
                                if allowedTargetPathEvents.contains($0.es_event_type) {
                                    return true
                                }
                                return false
                            }
                        }
                        return false
                    }) , id: \.self) { selectableEvent in
                        GroupBox {
                            HStack {
                                Toggle(isOn: $selectableEvents.first(where: { $0.eventString.wrappedValue == selectableEvent.eventString })!.selected) {
                                    HStack {
                                        Image(systemName: eventStringToImage(from: selectableEvent.eventString))
                                        Text(selectableEvent.eventString)
                                    }
                                }
                                Spacer()
                                Button {
                                    NSWorkspace.shared.open(URL(string:"https://developer.apple.com/documentation/endpointsecurity/es_event_type_t/\(selectableEvent.eventString)")!)
                                } label: {
                                    Image(systemName: "arrowshape.turn.up.backward.fill").help("Open developer docs.")
                                }
                            }
                        }
                    }
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
            Divider()
            HStack {
                Button("Mute path") {
                    // MARK: Step #1 in muting paths (globally)
                    // Send off the request and clear the field
                    // Gather the events the user wants to mute this path for
                    systemExtensionManager.puntPathToMute(pathToMute: pathToMute, muteCase: typeMuteMode, pathEvents: [])
                    pathToMute = ""
                    
                    // The reply carries the new saved set. Now close the sheet
                    withAnimation {
                        showPathMuteAddSheet.toggle()
                    }
                }.disabled(pathToMute.isEmpty)
                Button("Mute path events") {
                    // MARK: Step #1 in muting paths (for events)
                    systemExtensionManager.puntPathToMute(pathToMute: pathToMute, muteCase: typeMuteMode, pathEvents: Array(selectableEvents.filter({ $0.selected })).map(\.eventString))
                    pathToMute = ""
                    
                    // The reply carries the new saved set. Now close the sheet
                    withAnimation {
                        showPathMuteAddSheet.toggle()
                    }
                }.disabled(pathToMute.isEmpty || Array(selectableEvents.filter({ $0.selected })).isEmpty)
                Button("**Cancel**") {
                    withAnimation {
                        showPathMuteAddSheet.toggle()
                    }
                }.buttonStyle(.borderedProminent).tint(.pink).opacity(0.8)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading).padding(.all).transition(.scale)
        .onAppear {
            systemExtensionManager.requestEventSubscriptions()
        }
    }
}
