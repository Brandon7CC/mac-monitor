//
//  UserSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import SutroESFramework


struct Card: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(Color.white.opacity(0.4))
            .cornerRadius(5)
            .shadow(color: Color.black.opacity(0.8), radius: 5)
    }
}

extension View {
    func card() -> some View {
        modifier(Card())
    }
}

struct NonExecOptionsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    let randEventID: Int
    
    var body: some View {
        Group {
            Text("Event metadata")
            Divider()
            if userPrefs.contextInitiatingPathFilter {
                Text("Filter initiating path: \"`initiating_process_path`\"")
            }
            
            Text("Filter event: \"`ES_EVENT_TYPE_NOTIFY_EXEC`\"")
            
            if userPrefs.contextInitiatingEUIDFilter {
                Text("Filter `euid`: \"`root`\"")
            }
            
            Divider()
            Text("Advanced").opacity(0.6)
            if userPrefs.contextTargetPathFilter {
                Text("Filter target path: \"`target_path`\"")
            }
            
            if userPrefs.contextInitiatingPathMute {
                Text("Mute initiating path: \"`initiating_process_path`\"")
            }
            
            if userPrefs.contextTargetPathMute {
                Text("Mute target path events: \"`target_path`\"")
            }
        }
        
        Group {
            if userPrefs.contextEventUnsubscribe {
                Text("Unsubscribe: \"`ES_EVENT_TYPE_NOTIFY_EXEC`\"")
            }
        }
    }
}


struct ExecOptionsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    let randEventID: Int
    
    var body: some View {
        Group {
            Text("Event metadata")
            Divider()
            
            if userPrefs.contextTargetPathFilter {
                Text("Filter target path: \"`process_path`\"")
            }
            
            Text("Filter event: \"`ES_EVENT_TYPE_NOTIFY_EXEC`\"")
            
            if userPrefs.contextInitiatingEUIDFilter {
                Text("Filter `euid`: \"`root`\"")
            }
            
            if userPrefs.contextInitiatingPathFilter {
                Text("Filter initiating path: \"`initiating_process_path`\"")
            }
            
            Divider()
            Text("Advanced").opacity(0.6)
            
            if userPrefs.contextTargetPathMute {
                Text("Mute target path: \"`process_path`\"")
            }
            
            if userPrefs.contextInitiatingPathMute {
                Text("Mute initiating path: \"`initiating_process_path`\"")
            }
            
        }
        
        Group {
            if userPrefs.contextEventUnsubscribe {
                Text("Unsubscribe: \"`ES_EVENT_TYPE_NOTIFY_EXEC`\"")
            }
        }
    }
}


struct TableContextMenuPrefs: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    @State private var contextPreviewState = 0
    @State private var targetMuteSheetShowing: Bool = false
    
    let contextMenuHelp: String = """
    The below features, when selected, will appear in table context menus "right / secondary" clicking. A graphical preview is shown to the right. You can also independently customize this menu for process execution events.
    """
    
    let targetPathParentDirectory: String = """
    Muting / filtering a target path for the following events will be **based on the parent directory** when using the table context menus (\"right clicking\"). So, if a file was created at `~/Downloads/example.txt` when using the table context menus to mute or filter this target path we'll use the parent directory: `~/Downloads`.
    """
    
    let parentDirectoryTargetEvents: [String] = supportedEvents.map { event in
        eventTypeToString(from: event)
    }
    .filter {
        IntelligentEventTargeting.targetShouldBeParentDir(esEventType: $0)
    }
    
    
    var body: some View {
        VStack(alignment: .leading) {
            Label("**Table context menus**", systemImage: "computermouse").font(.title3).frame(maxWidth: .infinity, alignment: .leading)
            GroupBox {
                Text(contextMenuHelp).frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox {
                HStack {
                    Label("Muting / filtering target paths when using context menus (\"right clicking\") may vary by event type.", systemImage: "exclamationmark.triangle")
                    Button("More information") {
                        targetMuteSheetShowing.toggle()
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
                
            }.sheet(isPresented: $targetMuteSheetShowing) {
                VStack(alignment: .leading) {
                    Label("Context menu target path", systemImage: "questionmark.bubble").font(.title).padding(.bottom)
                    GroupBox {
                        Text(try! AttributedString(markdown: targetPathParentDirectory))
                    }
                    Divider()
                    List {
                        ForEach(parentDirectoryTargetEvents, id: \.self) { event in
                            GroupBox {
                                HStack {
                                    Image(systemName: eventStringToImage(from: event))
                                    Text("`\(event)`")
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    
                    HStack {
                        Spacer()
                        Button("Close") {
                            targetMuteSheetShowing.toggle()
                        }.buttonStyle(.borderedProminent).tint(.pink).padding(.all)
                        Spacer()
                    }.frame(alignment: .center)
                    
                }
                .frame(minWidth: 500.0, maxWidth: 500.0, minHeight: 400.0, maxHeight: 400.0, alignment: .topLeading)
                .padding(.all)
            }
            
            
            Picker("", selection: $contextPreviewState) {
                Text("All other events").tag(0)
                Text("Process execution events").tag(1)
            }
            .pickerStyle(.segmented)
            .padding(.bottom)
            
            Spacer()
            
            HStack {
                GroupBox {
                    VStack(alignment: .leading) {
                        let togglePadding: Double = 2.0
                        Text("**\(contextPreviewState == 0 ? "All other events" : "Process execution") artifact filtering**").underline()
                        Group {
                            // MARK: Settings toggles
                            Toggle("**Filter initiating process path**: `initiating_process_path`", isOn:
                                    contextPreviewState == 0 ? userPrefs.$contextInitiatingPathFilter : userPrefs.$contextExecInitiatingPathFilter
                            )
                            .padding(togglePadding)
                            
                            Toggle("**Filter target path**: `target_path`", isOn:
                                    contextPreviewState == 0 ? userPrefs.$contextTargetPathFilter : userPrefs.$contextExecTargetPathFilter
                            )
                            .padding(togglePadding)
                            
                            Toggle("**Filter initiating effective user ID**: `initiating_euid_human`", isOn:
                                    contextPreviewState == 0 ? userPrefs.$contextInitiatingEUIDFilter : userPrefs.$contextExecInitiatingEUIDFilter
                            )
                            .padding(togglePadding)
                            
                            
                            Text("\t**Note**: Not all events have a \"target path\"").padding(togglePadding)
                        }
                        
                        Divider().padding([.top, .bottom])
                        
                        Text("**\(contextPreviewState == 0 ? "All other events" : "Process execution") path muting**").underline()
                        Group {
                            Toggle("**Mute initiating process path**: `initiating_process_path`", isOn:
                                    contextPreviewState == 0 ? userPrefs.$contextInitiatingPathMute : userPrefs.$contextExecInitiatingPathMute
                            ).padding(togglePadding)
                            
                            Toggle("**Mute target path\(contextPreviewState == 0 ? " events" : "")**: `target_path`", isOn:
                                    contextPreviewState == 0 ? userPrefs.$contextTargetPathMute : userPrefs.$contextExecTargetPathMute
                            )
                            .padding(togglePadding)
                            Text("\t**Note**: Not all events have a \"target path\".")
                                .padding(togglePadding)
                        }
                        
                        Divider().padding([.top, .bottom])
                        
                        
                        Text("**\(contextPreviewState == 0 ? "All other events" : "Process execution") event subscriptions**").underline()
                        Toggle("**Unsubscribe from event type**: `es_event_type`", isOn:
                                contextPreviewState == 0 ? userPrefs.$contextEventUnsubscribe : userPrefs.$contextExecEventUnsubscribe
                        ).padding(togglePadding)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                }
                
                
                VStack(alignment: .center) {
                    let randEventID: Int = Int.random(in: 0..<120)
                    
                    VStack(alignment: .leading) {
                        // @note: show the context menu options for events other than process execution
                        if contextPreviewState == 0 {
                            NonExecOptionsView(randEventID: randEventID)
                                .environmentObject(systemExtensionManager)
                                .environmentObject(userPrefs)
                                .frame(alignment: .topLeading)
                        } else { // @note show the context menu options for process execution events
                            ExecOptionsView(randEventID: randEventID)
                                .environmentObject(systemExtensionManager)
                                .environmentObject(userPrefs)
                                .frame(alignment: .topLeading)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                    .padding([.leading, .top, .bottom])
                    .card()
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    
                    Spacer()
                    
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                Spacer()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            
            
            Spacer()
            
            Button("Reset context menu preferences") {
                userPrefs.resetContextPreferences()
//                        if contextPreviewState == 0 {
//                            userPrefs.resetNonExecPreferences()
//                        } else {
//                            userPrefs.resetExecPreferences()
//                        }
            }
            .help("Return the table context menus to their default configuration.")
            .frame(maxWidth: .infinity, alignment: .center)
            .padding([.top, .bottom])
            
            
        }.frame(maxWidth: .infinity)
    }
}

struct AppLifeCyclePrefsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    var lifeCycleHelp: String = """
    The below features control the app life cycle. For example, you can be warned before quitting the app. This might be useful if you accidently hit `⌘+Q`.
    """
    
    var body: some View {
        VStack(alignment: .leading) {
            Label("**App life cycle and state management**", systemImage: "autostartstop.trianglebadge.exclamationmark").font(.title3).frame(maxWidth: .infinity, alignment: .leading)
            HStack {
                GroupBox {
                    Text(lifeCycleHelp).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            
            GroupBox {
                HStack {
                    let togglePadding: Double = 2.0
                    
                    Toggle(isOn: userPrefs.$autoUpdates) {
                        Label("Auto update", systemImage: "square.and.arrow.down.badge.checkmark")
                    }.padding(togglePadding)
                    .disabled(!EndpointSecurityManager.supportsUpdates)
                    .help(EndpointSecurityManager.supportsUpdates ? "" : "Community builds don't update themselves.")
                    
                    Toggle(isOn: userPrefs.$lifecycleWarnBeforeQuit) {
                        Label("Warn before **quitting** the app?", systemImage: "exclamationmark.octagon")
                    }.padding(togglePadding)
                    
                    Toggle(isOn: userPrefs.$lifecycleWarnBeforeClear) {
                        Label("Warn before **clearing** events?", systemImage: "windshield.rear.and.wiper.exclamationmark")
                    }.padding(togglePadding)
                }
                .frame(maxWidth: .infinity, alignment: .center)
            }
            
        }.frame(maxWidth: .infinity)
    }
}


struct UserSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading) {
                GroupBox {
                    VStack(alignment: .leading) {
                        HStack {
                            Image(systemName: "gear.badge.checkmark")
                            Text("**User preferences**").frame(alignment: .leading).font(.title2)
                            Text("Persist across app launches").frame(maxWidth: .infinity, alignment: .leading).font(.callout)
                            Spacer()
                            Button("Reset all") {
                                userPrefs.resetAllPreferences()
                            }.buttonStyle(.borderedProminent).tint(.green).opacity(0.8)
                        }
                    }
                }
                
                Divider()
                
                GroupBox {
                    VStack(alignment: .leading) {
                        HStack {
                            Toggle("Forks as parents", isOn: userPrefs.$forksAsParent)
                                .bold()
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        
                        Text("Show forks as parents in process subtrees.")
                    }
                }
                
                Divider()
                
                GroupBox {
                    VStack {
                        AppLifeCyclePrefsView()
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    }.frame(alignment: .topLeading)
                    
                }
                
                Divider()
                
                GroupBox {
                    TableContextMenuPrefs()
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                }
            }.frame(alignment: .topLeading)
        }
    }
}
