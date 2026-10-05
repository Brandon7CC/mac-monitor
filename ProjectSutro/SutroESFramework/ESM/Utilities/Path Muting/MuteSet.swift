//
//  MuteSet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/11/25.
//

import Foundation

/// The default Mac Monitor mute set, as rules. ``MuteList/shippedDefault(for:)`` merges it by path and type: what a
/// new saved mute set starts from and what Reset restores.
public struct MuteSet {
    /// Rules that mute specific event types for a given path.
    let eventSpecificRules: [(eventType: es_event_type_t, muteType: es_mute_path_type_t, paths: [String])]
    
    /// Rules that mute all event types for a given path.
    let globalRules: [(pathType: es_mute_path_type_t, paths: [String])]
    
    /// Mac Monitor's default mute set, for one home folder.
    ///
    /// Two rules are per user: files created and renamed in `~/Library/Caches/`, and extended attributes read from
    /// files in `~/Library/Biome/streams/`. The Security Extension runs as root, so it passes the console user's home
    /// (``ConsoleUser``), never its own.
    ///
    /// - Parameter home: The home folder those two rules mute, or `nil` to leave them out (no one is logged in).
    /// - Returns: The rules.
    public static func `default`(home: String?) -> MuteSet {
        let caches = homePaths("Library/Caches", in: home)
        let biomeStreams = homePaths("Library/Biome/streams", in: home)
        
        // MARK: - Event-Specific Mute Rules
        var eventRules = [
            (eventType: ES_EVENT_TYPE_NOTIFY_CREATE, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/sbin/cfprefsd",
                "/usr/libexec/logd",
                "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/system_installd",
                "/System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookManager.app/Contents/MacOS/AddressBookManager",
                "/usr/libexec/mobileassetd",
                "/usr/libexec/biomesyncd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_CLOSE, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/runningboardd",
                "/usr/libexec/biomesyncd",
                "/System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc/Contents/MacOS/MTLCompilerService",
                "/usr/libexec/containermanagerd"
            ]),
            
            (eventType: ES_EVENT_TYPE_NOTIFY_CREATE, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: caches + [
                "/System/Library/PrivateFrameworks/BiomeStreams.framework"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_RENAME, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/sbin/cfprefsd",
                "/usr/libexec/logd",
                "/usr/libexec/mobileassetd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_RENAME, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: caches),
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
                "/usr/libexec/mobileassetd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_MPROTECT, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
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
                "/usr/libexec/mobileassetd"
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
            (eventType: ES_EVENT_TYPE_NOTIFY_GETEXTATTR, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/runningboardd",
                "/usr/libexec/containermanagerd",
                "/System/Library/CoreServices/TimeMachine/backupd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_GETEXTATTR, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/Library/SystemExtensions/",
                "/System/Library/PrivateFrameworks/"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_GETEXTATTR, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX,
             paths: biomeStreams),
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
    
    /// A folder in a home folder, as a prefix rule's paths.
    ///
    /// The path ends in `/`: Endpoint Security matches a prefix as a string, so without it `~/Library/Caches` would
    /// also mute `~/Library/CachesX`, a sibling the user can create.
    ///
    /// - Parameters:
    ///   - relative: The folder, relative to the home folder.
    ///   - home: The home folder, if any.
    /// - Returns: The folder's path, ending in `/`, or nothing without a home folder or when it's too long to mute.
    static func homePaths(_ relative: String, in home: String?) -> [String] {
        guard let home else { return [] }
        let path = URL(fileURLWithPath: home, isDirectory: true).appendingPathComponent(relative).path + "/"
        return path.utf8.count <= MuteLimits.maxPathBytes ? [path] : []
    }
}
