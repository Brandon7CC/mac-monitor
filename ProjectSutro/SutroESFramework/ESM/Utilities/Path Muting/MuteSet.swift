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
    /// Xcode's tools are muted only when root owns Xcode (``ownsXcode(_:at:)``). An Xcode expanded from a `.xip`
    /// belongs to whoever expanded it, so a program they put inside would run unseen.
    ///
    /// - Parameters:
    ///   - home: The home folder those two rules mute, or `nil` to leave them out (no one is logged in).
    ///   - mutesXcode: Mute Xcode's tools. By default, if root owns Xcode.
    ///   - mutesXPCConnects: Include the XPC connect mutes. By default, on macOS 14 and later, which added the event.
    ///     Upgrades pass `false` to find a set first saved on macOS 13.
    /// - Returns: The rules.
    public static func `default`(home: String?, mutesXcode: Bool? = nil, mutesXPCConnects: Bool? = nil) -> MuteSet {
        let mutesXcode = mutesXcode ?? ownsXcode()
        let caches = homePaths("Library/Caches", in: home)
        let biomeStreams = homePaths("Library/Biome/streams", in: home)
        /// Processes muted for both mmap and mprotect.
        let mappers: [String] = [
            "/usr/bin/tailspin",
            "/usr/libexec/spindump",
            "/private/var/db/KernelExtensionManagement/KernelCollections/BootKernelCollection.kc",
            "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/"
                + "Support/mdworker_shared",
            "/System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc/Contents/MacOS/"
                + "MTLCompilerService",
            "/usr/libexec/knowledge-agent",
            "/usr/libexec/locationd",
            "/System/Library/PrivateFrameworks/BiomeStreams.framework/Support/BiomeAgent",
            "/usr/libexec/xpcproxy",
            "/usr/libexec/opendirectoryd",
            "/System/Library/Frameworks/CoreSpotlight.framework/spotlightknowledged",
            "/usr/libexec/mobileassetd",
            /// Maps system frameworks in bursts after apps are installed. It runs only from the sealed system volume.
            "/usr/libexec/spotlightknowledged.updater"
        ]
        /// Daemons that save their own state as property lists and logs: the scheduler's and the log helper's
        /// temporary files, created, closed, renamed into place and set read-only. Not logd_helper's mmaps: it maps
        /// each program run for the first time, a cheap tell of something new.
        let stateWriters = ["/usr/libexec/dasd", "/usr/libexec/logd_helper"]
        
        // MARK: - Event-Specific Mute Rules
        var eventRules = [
            (eventType: ES_EVENT_TYPE_NOTIFY_CREATE, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/sbin/cfprefsd",
                "/usr/libexec/logd",
                "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/system_installd",
                "/System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookManager.app/Contents/MacOS/AddressBookManager",
                "/usr/libexec/mobileassetd",
                "/usr/libexec/biomesyncd"
            ] + stateWriters),
            (eventType: ES_EVENT_TYPE_NOTIFY_CLOSE, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/runningboardd",
                "/usr/libexec/biomesyncd",
                "/System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc/Contents/MacOS/MTLCompilerService",
                "/usr/libexec/containermanagerd"
            ] + stateWriters),
            
            (eventType: ES_EVENT_TYPE_NOTIFY_CREATE, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: caches + [
                "/System/Library/PrivateFrameworks/BiomeStreams.framework"
            ]),
            /// Not cfprefsd: it saves every preference as a temporary file renamed over the .plist, so its renames are
            /// the property list writes the Plist modified indicator looks for, `defaults write` into
            /// ~/Library/LaunchAgents among them. Its closes, of those temporary files, stay muted.
            (eventType: ES_EVENT_TYPE_NOTIFY_RENAME, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/logd",
                "/usr/libexec/mobileassetd"
            ] + stateWriters),
            (eventType: ES_EVENT_TYPE_NOTIFY_RENAME, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: caches),
            (eventType: ES_EVENT_TYPE_NOTIFY_OPEN, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [
                "/usr/libexec/xpcproxy",
                "/usr/sbin/cfprefsd",
                "/Library/SystemExtensions/",
                "/System/Library/CoreServices/Spotlight.app",
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
            /// Every process a terminal starts closes its standard streams on the terminal when it exits, each a
            /// modified close: most closes during terminal use. `process.tty` names the terminal already. Serial
            /// devices (`/dev/tty.*`) and disks (`/dev/disk*`, `/dev/rdisk*`) stay seen.
            (eventType: ES_EVENT_TYPE_NOTIFY_CLOSE, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: [
                "/dev/ttys"
            ]),
            /// launchd's own log, closed after every job it starts. Its unlink and rename stay seen; a rewrite in place
            /// by root does not, as the default stream has no write or open.
            (eventType: ES_EVENT_TYPE_NOTIFY_CLOSE, muteType: ES_MUTE_PATH_TYPE_TARGET_LITERAL, paths: [
                "/dev/console",
                "/private/var/log/com.apple.xpc.launchd/launchd.log"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: mappers),
            /// The shared web credentials daemon maps every app's apple-app-site-association JSON from its cache in
            /// /private/var/folders: over a third of an idle Mac's mmaps, and never code.
            (eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: [
                "/usr/libexec/swcd"
            ]),
            (eventType: ES_EVENT_TYPE_NOTIFY_MPROTECT, muteType: ES_MUTE_PATH_TYPE_LITERAL, paths: mappers),
            (eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_TARGET_PREFIX, paths: [
                "/Library/Caches/",
                "/private/var/db/",
                "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
                /// Media analysis models, mapped while the Mac is idle. On the sealed system volume.
                "/System/Library/PrivateFrameworks/MediaAnalysis.framework/Versions/A/Resources/"
            ]),
            /// Files mapped over and over while the Mac is idle: the Secure Enclave and Bluetooth daemons' own
            /// programs, and the symbolication cache. Only for mmap: a target mute for every event would also hide
            /// these programs' execs. Root can write the cache folder with SIP on, but a file planted there is still
            /// seen as it's created, renamed and closed, so Mach-O written still fires.
            (eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_TARGET_LITERAL, paths: [
                "/usr/libexec/seputil",
                "/usr/sbin/bluetoothd",
                "/System/Library/Caches/com.apple.coresymbolicationd/data"
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
            ] + stateWriters)
        ]
        
        if mutesXcode {
            eventRules += [
                (eventType: ES_EVENT_TYPE_NOTIFY_PROC_CHECK, muteType: ES_MUTE_PATH_TYPE_PREFIX, paths: [xcode + "/"]),
                (eventType: ES_EVENT_TYPE_NOTIFY_MMAP, muteType: ES_MUTE_PATH_TYPE_PREFIX,
                 paths: [xcode + "/Contents/SharedFrameworks/"])
            ]
        }
        
        if mutesXPCConnects ?? hasXPCConnects {
            let sonomaRules = [
                /// Daemons that connect to services all day: the launcher every XPC service starts through, the Wi-Fi
                /// menu, the scheduler and the agent that runs launchd's event plug-ins. Endpoint Security can only
                /// mute XPC connects by the connecting process. Not siriactionsd: its connects are how a Shortcut that
                /// runs in the background is seen.
                (ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, ES_MUTE_PATH_TYPE_LITERAL, [
                    "/usr/sbin/bluetoothd",
                    "/usr/libexec/airportd",
                    "/usr/libexec/xpcproxy",
                    "/System/Library/CoreServices/WiFiAgent.app/Contents/MacOS/WiFiAgent",
                    "/usr/libexec/dasd",
                    "/usr/libexec/UserEventAgent"
                ])
            ]
            eventRules.append(contentsOf: sonomaRules)
        }
        
        // MARK: - Global Mute Rules
        var globalRules = [
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
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework"
            ]),
            (pathType: ES_MUTE_PATH_TYPE_TARGET_LITERAL, paths: [
                "/usr/sbin/spindump",
                "/usr/libexec/tailspind",
                "/dev/null",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared"
            ])
        ]
        
        if mutesXcode {
            globalRules.append((pathType: ES_MUTE_PATH_TYPE_PREFIX, paths: [xcodeToolchain(xcode) + "/"]))
        }
        
        return MuteSet(eventSpecificRules: eventRules, globalRules: globalRules)
    }
    
    /// Does this macOS have XPC connect events (macOS 14 and later)?
    static var hasXPCConnects: Bool {
        if #available(macOS 14, *) { return true }
        return false
    }
    
    /// Where Xcode is installed.
    static let xcode = "/Applications/Xcode.app"
    
    /// Xcode's default toolchain, whose compilers and linkers a build runs thousands of times.
    ///
    /// - Parameter xcode: Xcode's bundle.
    /// - Returns: The toolchain's path.
    static func xcodeToolchain(_ xcode: String) -> String {
        xcode + "/Contents/Developer/Toolchains/XcodeDefault.xctoolchain"
    }
    
    /// Can only `owner` change the folders Xcode's mutes cover, and the folders above them in the bundle?
    ///
    /// - Parameters:
    ///   - owner: Who must own them. Root, except in tests.
    ///   - xcode: Xcode's bundle.
    /// - Returns: `true` if each is a directory `owner` owns, that neither its group, others, nor an access control
    ///   entry lets anyone else change.
    static func ownsXcode(_ owner: uid_t = 0, at xcode: String = xcode) -> Bool {
        let folders = [xcode, xcode + "/Contents", xcode + "/Contents/SharedFrameworks", xcode + "/Contents/Developer",
                       xcode + "/Contents/Developer/Toolchains", xcodeToolchain(xcode)]
        return folders.allSatisfy { folder in
            var info = stat()
            guard lstat(folder, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == owner,
                  info.st_mode & (S_IWGRP | S_IWOTH) == 0 else { return false }
            return CommandLineToolLink.entryWriter(of: folder) == nil
        }
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
        let path = home.appendingPathComponent(relative) + "/"
        return path.utf8.count <= MuteLimits.maxPathBytes ? [path] : []
    }
}
