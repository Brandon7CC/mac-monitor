//
//  MuteSet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/11/25.
//

import Foundation

/// The default Mac Monitor mute set.
///
public struct MuteSet {
    /// Rules that mute specific event types for a given path.
    let eventSpecificRules: [(eventType: es_event_type_t, muteType: es_mute_path_type_t, paths: [String])]
    
    /// Rules that mute all event types for a given path.
    let globalRules: [(pathType: es_mute_path_type_t, paths: [String])]
    
    /// Mac Monitor's default mute set
    public static var `default`: MuteSet {
        // This directory path is calculated at runtime.
        let caches_dir = String(
            URL(fileURLWithPath: NSHomeDirectory())
                .appendingPathComponent("Library/Caches").path
        )
        
        // MARK: - Event-Specific Mute Rules
        var eventRules = [
            (eventType: ES_EVENT_TYPE_NOTIFY_CREATE, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/sbin/cfprefsd",
                "/usr/libexec/logd",
                "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/system_installd",
                "/System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookManager.app/Contents/MacOS/AddressBookManager",
                "/usr/libexec/mobileassetd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_CLOSE, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/runningboardd",
                "/usr/libexec/biomesyncd",
                "/System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc/Contents/MacOS/MTLCompilerService",
                "/usr/libexec/containermanagerd"
            ]),
            
            (eventType: ES_EVENT_TYPE_NOTIFY_CREATE, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: [
                caches_dir,
                "/System/Library/PrivateFrameworks/BiomeStreams.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_RENAME, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/sbin/cfprefsd",
                "/usr/libexec/logd",
                "/usr/libexec/mobileassetd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_RENAME, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: [caches_dir]),
            (eventType: ES_EVENT_TYPE_NOTIFY_OPEN, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/usr/libexec/xpcproxy",
                "/usr/sbin/cfprefsd",
                "/Library/SystemExtensions/",
                "/System/Library/CoreServices/Spotlight.app",
                "/Library/SystemExtensions/",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
                "/System/Library/PrivateFrameworks/SkyLight.framework",
                "/System/Library/PrivateFrameworks/AXAssetLoader.framework",
                "/System/Library/Frameworks/AudioToolbox.framework",
                "/System/Library/PrivateFrameworks/SiriTTSService.framework",
                "/System/Library/PrivateFrameworks/TCC.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_WRITE, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/Library/SystemExtensions/",
                "/usr/libexec/lsd",
                "/usr/sbin/cfprefsd",
                "/System/Library/CoreServices/Spotlight.app",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
                "/usr/sbin/systemstats"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_CLOSE, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/Library/SystemExtensions/",
                "/usr/libexec/lsd",
                "/usr/sbin/cfprefsd",
                "/usr/libexec/xpcproxy",
                "/System/Library/CoreServices/Spotlight.app",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
                "/System/Library/PrivateFrameworks/AXAssetLoader.framework",
                "/System/Library/PrivateFrameworks/SiriTTSService.framework",
                "/System/Library/CoreServices/NotificationCenter.app",
                "/usr/sbin/systemstats",
                "/System/Library/PrivateFrameworks/TCC.framework",
                "/usr/libexec/mobileassetd",
                "/System/Library/PrivateFrameworks/SkyLight.framework",
                "/System/Library/Frameworks/AudioToolbox.framework",
                "/System/Library/PrivateFrameworks/BiomeStreams.framework",
                "/System/Library/CoreServices/ManagedClient.app",
                "/System/Library/Frameworks/Contacts.framework",
                "/System/Library/Frameworks/VideoToolbox.framework",
                "/System/Library/PrivateFrameworks/CoreDuetContext.framework",
                "/System/Library/CoreServices/diagnostics_agent"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/bin/tailspin",
                "/usr/libexec/spindump",
                "/private/var/db/KernelExtensionManagement/KernelCollections/BootKernelCollection.kc",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
                "/System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc/Contents/MacOS/MTLCompilerService",
                "/usr/libexec/knowledge-agent",
                "/usr/libexec/locationd",
                "/System/Library/PrivateFrameworks/BiomeStreams.framework/Support/BiomeAgent",
                "/usr/libexec/xpcproxy",
                "/usr/libexec/opendirectoryd",
                "/System/Library/Frameworks/CoreSpotlight.framework/spotlightknowledged",
                "/usr/libexec/mobileassetd",
                ""
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: [
                "/Library/Caches/",
                "/private/var/db/",
                "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_DUP, muteType: ES_MUTE_PATH_TYPE_TARGET_LITERAL, paths: [
                "/dev/null",
                "/dev/console"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_DUP, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
                "/System/Library/PrivateFrameworks/BiomeStreams.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_DUP, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/xpcproxy",
                "/usr/sbin/cfprefsd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_PROC_CHECK, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/usr/libexec/sysmond",
                "/Applications/Xcode.app",
                "/usr/sbin/systemstats",
                "/System/Library/PrivateFrameworks/CoreDuetContext.framework",
                "/System/Library/PrivateFrameworks/CoreAnalytics.framework",
                "/usr/sbin/mDNSResponder",
                "/usr/libexec/trustd",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
                "/usr/sbin/distnoted",
                "/usr/libexec/mobileassetd",
                "/System/Library/PrivateFrameworks/SiriTTSService.framework",
                "/usr/sbin/cfprefsd",
                "/usr/libexec/xpcproxy",
                "/System/Library/PrivateFrameworks/DataAccess.framework",
                "/System/Library/Frameworks/Contacts.framework",
                "/System/Library/Frameworks/Accounts.framework",
                "/System/Library/PrivateFrameworks/CalendarDaemon.framework",
                "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/ATS.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_CREATE, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/System/Library/PrivateFrameworks/StreamingExtractor.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_SETMODE, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/System/Library/PrivateFrameworks/StreamingExtractor.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/Applications/Xcode.app/Contents/SharedFrameworks"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_EXIT, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_PROC_CHECK, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
                "/usr/libexec/airportd",
                "/usr/libexec/usermanagerd",
                "/usr/libexec/containermanagerd",
                "/System/Library/PrivateFrameworks/CloudKitDaemon.framework/support/cloudd",
                "/usr/libexec/rosetta/oahd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/PerfPowerServices"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_SETMODE, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/sbin/cfprefsd",
                "/usr/libexec/mobileassetd"
            ])
        ]

        if #available(macOS 14, *) {
            let sonomaRules = [
                (ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, ES_MUTE_PATH_TYPE_LITERAL, [
                    "/usr/sbin/bluetoothd",
                    "/usr/libexec/airportd"
                ])
            ]
            eventRules.append(contentsOf: sonomaRules)
        }
        
        // MARK: - Global Mute Rules
        let globalRules = [
            (pathType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/logd",
                "/System/Library/CoreServices/Diagnostics Reporter.app/Contents/MacOS/Diagnostics Reporter",
                "/usr/libexec/ReportMemoryException",
                "/usr/sbin/spindump",
                "/System/Library/PrivateFrameworks/BiomeStreams.framework/Support/BiomeAgent",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
                "/usr/libexec/duetexpertd",
                "/System/Library/PrivateFrameworks/HelpData.framework/Versions/A/Resources/helpd"
            ]),
            (pathType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework"
            ]),
            (pathType: ES_MUTE_PATH_TYPE_TARGET_LITERAL, paths: [
                "/usr/sbin/spindump",
                "/usr/libexec/tailspind",
                "/dev/null",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared"
            ])
        ]
        
        return MuteSet(eventSpecificRules: eventRules, globalRules: globalRules)
    }
}

extension MuteSet {
    private struct EventRuleKey: Hashable {
        let eventType: es_event_type_t
        let muteType: es_mute_path_type_t
    }
    
    private struct GlobalRule: Hashable {
        let pathType: es_mute_path_type_t
        let path: String
    }
    
    private struct EventRule: Hashable {
        let eventType: es_event_type_t
        let muteType: es_mute_path_type_t
        let path: String
    }
    
    // Creates a MuteSet by grouping an array of ESMutedPath JSON strings.
    public init(from mutedPathJSONs: [String]) {
        let parsedPaths = mutedPathJSONs.compactMap { jsonString in
            decodePathJSON(pathJSON: jsonString)
        }
        
        var eventSpecificBuilder = [EventRuleKey: Set<String>]()
        var globalBuilder = [es_mute_path_type_t: Set<String>]()

        for mutedPath in parsedPaths {
            let muteType = getMuteCaseFromString(muteString: mutedPath.type)
            if mutedPath.events.isEmpty {
                globalBuilder[muteType, default: []].insert(mutedPath.path)
            } else {
                for eventString in mutedPath.events {
                    let eventType = eventStringToType(from: eventString)
                    let key = EventRuleKey(eventType: eventType, muteType: muteType)
                    eventSpecificBuilder[key, default: []].insert(mutedPath.path)
                }
            }
        }

        self.eventSpecificRules = eventSpecificBuilder.map { (key, paths) in
            (eventType: key.eventType, muteType: key.muteType, paths: Array(paths))
        }

        self.globalRules = globalBuilder.map { (pathType, paths) in
            (pathType: pathType, paths: Array(paths))
        }
    }
}
