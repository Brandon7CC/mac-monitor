//
//  DefaultIndicatorSource.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - The default indicators' source
/// What generates `SutroESFramework/Detection/DefaultIndicators.json`, the indicators Mac Monitor ships. The file
/// names its format and version as an exported one does (``IndicatorExchange``) and lists
/// ``Indicator/sourceDefaults`` as `indicators`. The framework's binary holds the file (``DefaultIndicators``), and
/// nothing here ships.
///
/// Each default's number (``Indicator/uuid(_:)``) is its identity on every Mac, in every saved set and every verdict a
/// trace keeps. A number is never given to another indicator, not even once its own is dropped: those dropped are
/// ``Indicator/retiredNumbers``. A change to a default reaches every Mac that didn't edit it; one someone edited keeps
/// their edit (``SavedIndicators``).
///
/// Each predicate is built here from named parts that say what they're for, since JSON has no comments and repeats
/// what predicates share. `ProjectSutro/Scripts/generate-default-indicators.sh` writes the file again after a change.
enum DefaultIndicatorSource {
    /// The file's top level.
    private struct File: Encodable {
        let format = IndicatorExchange.format
        let version = IndicatorExchange.version
        let indicators = Indicator.sourceDefaults
    }

    /// The file's text: pretty-printed with its keys sorted, as an exported file is, and a newline at its end.
    static var text: String {
        get throws {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            return String(decoding: try encoder.encode(File()), as: UTF8.self) + "\n"
        }
    }
}


// MARK: - Defaults
extension Indicator {
    /// The numbers earlier builds dropped: the defaults Not quarantined (2), osascript (12) and Non-Apple as root
    /// (14), and the built-in marks that 3.1.0's defaults replaced (34, 36 to 39). They're never given to another
    /// indicator. The marks Elevated to root (16), BTM database modified (24), Background item removed (25), HID
    /// device opened (26), Remote thread created (27), Code signature invalidated (28), Process traced (29) and Task
    /// port retrieved (30) became the defaults with their numbers.
    static let retiredNumbers = [2, 12, 14, 34, 36, 37, 38, 39]

    /// The indicators Mac Monitor ships, each with an identity of its own, so Restore Defaults puts back the same ones:
    /// what ``defaults`` reads from the file.
    ///
    /// Each has the severity its evidence earns: high only for an XProtect detection, which is malware macOS itself
    /// found; medium for persistence, injection, payloads, password checks and privacy permissions written around
    /// tccd, which are suspicious but have benign uses (a new executable, an inserted dylib, a login hook, a change to
    /// authentication, a password checked with dscl, a TCC database written); and low for context and what's often
    /// benign (a login, a download tool, a plist, an archive or a compiled script written, quarantine removed, a
    /// keychain opened, a name resolved by unsigned code).
    static let sourceDefaults: [Indicator] = [
        Indicator(id: uuid(1), name: "Reflective loading",
                  description: "Wrote or mapped the image NSCreateObjectFileImageFromMemory makes to load a Mach-O "
                    + "from memory.",
                  symbol: "memorychip", color: .red,
                  predicate: type("CREATE", "WRITE", "MMAP")
                    + #" AND target_path CONTAINS "/NSCreateObjectFileImageFromMemory-""#,
                  tables: [.dot, .symbol, .label],
                  tactic: .defenseEvasion, technique: "T1620",
                  severity: .medium),
        Indicator(id: uuid(3), name: "Quarantine removed",
                  description: "Deleted a file's quarantine attribute, so Gatekeeper won't check it when it's "
                    + "opened.",
                  symbol: "xmark.shield", color: .red,
                  predicate: type("DELETEEXTATTR") + #" AND event.deleteextattr.extattr ENDSWITH "apple.quarantine""#,
                  tables: [.dot, .symbol, .label],
                  tactic: .defenseEvasion, technique: "T1553.001",
                  severity: .low),
        Indicator(id: uuid(4), name: "Background item added",
                  description: "Added a background item, which runs again at login.",
                  symbol: "gearshape.2", color: .orange, predicate: type("BTM_LAUNCH_ITEM_ADD"),
                  tables: [.dot, .label],
                  tactic: .persistence, technique: "T1543.001",
                  severity: .low),
        Indicator(id: uuid(5), name: "XProtect detection",
                  description: "XProtect detected or remediated malware.",
                  symbol: "xmark.octagon", color: .purple,
                  predicate: type("XP_MALWARE_DETECTED", "XP_MALWARE_REMEDIATED"),
                  tables: [.dot, .symbol, .label],
                  severity: .high),
        Indicator(id: uuid(6), name: "AppleScript / JXA",
                  description: "Mapped a scripting component, as a process running AppleScript or JXA does.",
                  symbol: "applescript", color: .purple,
                  predicate: type("MMAP") + #" AND (target_path CONTAINS "AppleScript.component" "#
                    + #"OR target_path CONTAINS "JavaScript.component" OR target_path CONTAINS ".osax")"#,
                  tables: [.dot, .symbol, .label],
                  tactic: .execution, technique: "T1059.002",
                  severity: .low),
        // The keychain daemons' own opens, and macOS's certificate keychains, are left out.
        Indicator(id: uuid(7), name: "Keychain opened",
                  description: "Opened a keychain file, which holds passwords and keys, as a stealer copying "
                    + "login.keychain-db does.",
                  symbol: "key", color: .blue,
                  predicate: type("OPEN") + #" AND target_path CONTAINS "/Library/Keychains/" "#
                    + #"AND NOT target_path BEGINSWITH "/System/" AND NOT process.executable.path IN {"#
                    + keychainDaemons.map { #""\#($0)""# }.joined(separator: ", ") + "}",
                  tactic: .credentialAccess, technique: "T1555.001",
                  severity: .low),
        Indicator(id: uuid(8), name: "Login",
                  description: "Logged in, or failed to, at the login window, with login(1) or over SSH.",
                  symbol: "person.badge.key", color: .blue,
                  predicate: type("LOGIN_LOGIN", "LW_SESSION_LOGIN", "OPENSSH_LOGIN"),
                  tactic: .initialAccess, technique: "T1078",
                  severity: .low),
        Indicator(id: uuid(9), name: "New executable",
                  description: "Ran an executable created less than a second earlier, as a dropper's payload is.",
                  symbol: "clock.badge.exclamationmark", color: .orange, predicate: newExecutableSource,
                  tables: [.dot, .symbol],
                  tactic: .execution, technique: "T1204.002",
                  severity: .medium),
        Indicator(id: uuid(10), name: "Adhoc signed",
                  description: "Ran adhoc signed code, as a freshly compiled or modified binary is.",
                  symbol: "xmark.seal", color: .orange, predicate: adhocSignedPredicate,
                  tables: [.dot, .symbol, .label],
                  tactic: .defenseEvasion, technique: "T1553.002",
                  severity: .low),
        Indicator(id: uuid(61), name: "Unsigned",
                  description: "Ran code with no signature, or one that's no longer valid.",
                  symbol: "xmark.seal", color: .red, predicate: unsignedPredicate,
                  tables: [.dot, .symbol, .label],
                  tactic: .defenseEvasion, technique: "T1553.002",
                  severity: .low),
        Indicator(id: uuid(11), name: "Ran a script",
                  description: "An interpreter ran a script, which the exec's Script tab shows.",
                  symbol: "scroll.fill", color: .purple,
                  predicate: type("EXEC") + #" AND event.exec.script_content != nil "#
                    + #"AND event.exec.script_content != """#,
                  tables: [.dot, .symbol],
                  tactic: .execution, technique: "T1059",
                  severity: .low),
        Indicator(id: uuid(13), name: "Download tool",
                  description: "Ran a command line download tool, as a dropper does to fetch its payload.",
                  symbol: "arrow.down.circle", color: .blue,
                  predicate: type("EXEC") + " AND event.exec.target.executable.name "
                    + #"IN {"curl", "wget", "nscurl", "ftp", "tftp", "scp", "sftp"}"#,
                  tactic: .commandAndControl, technique: "T1105",
                  severity: .low),
        // The driver is known only for events Mac Monitor 3.1.0 or later recorded.
        Indicator(id: uuid(41), name: "Non-Apple driver opened",
                  description: "Opened a service whose driver is a third-party kext or DriverKit extension.",
                  symbol: "puzzlepiece.extension", color: .orange, predicate: nonAppleDriverPredicate,
                  tactic: .privilegeEscalation, technique: "T1068",
                  severity: .low),
        // A .plist closed after it was written, or renamed into place, as a safe save and cfprefsd do.
        Indicator(id: uuid(42), name: "Plist modified",
                  description: "Wrote a property list, such as a launch agent's, an app's Info.plist or its "
                    + "preferences.",
                  symbol: "doc.badge.gearshape", color: .yellow, predicate: modifiedPropertyListPredicate,
                  tactic: .defenseEvasion, technique: "T1647",
                  severity: .low),
        // Object files and core dumps aren't runnable, so they're left out.
        Indicator(id: uuid(43), name: "Mach-O written",
                  description: "Wrote a Mach-O executable, dylib or bundle, whatever its name, as a dropper writes "
                    + "its payload.",
                  symbol: "arrow.down.doc", color: .orange, predicate: machOWrittenPredicate,
                  tactic: .commandAndControl, technique: "T1105",
                  severity: .medium),
        // T1574.007 too, for a PATH entry.
        Indicator(id: uuid(44), name: "Shell startup file modified",
                  description: "Wrote a file a shell runs as it starts, such as ~/.zshrc or /etc/paths.d, so a "
                    + "command runs in every new shell.",
                  symbol: "terminal", color: .yellow, predicate: shellStartupPredicate,
                  tactic: .persistence, technique: "T1546.004",
                  severity: .low),
        // T1053.002 too, for an at job.
        Indicator(id: uuid(45), name: "Scheduled job added",
                  description: "Added a cron table or at job, or turned on atrun, to run a command on a schedule.",
                  symbol: "calendar.badge.clock", color: .green, predicate: scheduledJobPredicate,
                  tactic: .persistence, technique: "T1053.003",
                  severity: .medium),
        // T1556 too. Editors' and visudo's temporary files, and removing a right, are left out.
        Indicator(id: uuid(46), name: "Authentication modified",
                  description: "Changed sudo, PAM, an authorization plugin or right, or an OpenDirectory module, as "
                    + "a backdoor that grants root or captures passwords does.",
                  symbol: "lock.open", color: .blue, predicate: authenticationModifiedPredicate,
                  tactic: .credentialAccess, technique: "T1556",
                  severity: .medium),
        Indicator(id: uuid(47), name: "SSH access modified",
                  description: "Wrote an authorized_keys file or sshd's configuration, which keeps remote access "
                    + "open.",
                  symbol: "network.badge.shield.half.filled", color: .blue, predicate: sshAccessPredicate,
                  tactic: .persistence, technique: "T1098.004",
                  severity: .medium),
        // An External Extensions file, or -load-extension=, which branded Chrome ignores from version 137.
        Indicator(id: uuid(48), name: "Browser extension sideloaded",
                  description: "Added a Chromium extension the Web Store didn't, as adware does.",
                  symbol: "globe", color: .orange, predicate: browserExtensionPredicate,
                  tactic: .persistence, technique: "T1176.001",
                  severity: .medium),
        Indicator(id: uuid(49), name: "Launch job loaded",
                  description: "Loaded a launchd job with launchctl from outside the folders Background Task "
                    + "Management reports.",
                  symbol: "gearshape.arrow.triangle.2.circlepath", color: .orange, predicate: launchJobLoadedPredicate,
                  tactic: .execution, technique: "T1569.001",
                  severity: .medium),
        // dyld ignores it for platform, setuid and hardened programs.
        Indicator(id: uuid(50), name: "Dylib inserted",
                  description: "Ran a program with DYLD_INSERT_LIBRARIES set, so dyld loads another dylib into it.",
                  symbol: "bookmark.slash", color: .red, predicate: dylibInsertedPredicate,
                  tables: [.dot, .symbol],
                  tactic: .defenseEvasion, technique: "T1574.006",
                  severity: .medium),
        Indicator(id: uuid(51), name: "Plug-in installed",
                  description: "Added a plug-in macOS loads on its own, such as a screen saver, Spotlight importer "
                    + "or input method.",
                  symbol: "powerplug", color: .orange, predicate: pluginInstalledPredicate,
                  tactic: .persistence, technique: "T1546",
                  severity: .medium),
        Indicator(id: uuid(52), name: "Terminal startup command",
                  description: "Set a command Terminal or iTerm2 runs as it starts or opens a window.",
                  symbol: "apple.terminal", color: .yellow, predicate: terminalStartupPredicate,
                  tactic: .persistence, technique: "T1546",
                  severity: .medium),
        Indicator(id: uuid(53), name: "Login hook set",
                  description: "Set a login or logout hook, a script loginwindow runs as root.",
                  symbol: "person.badge.clock", color: .orange, predicate: loginHookPredicate,
                  tactic: .persistence, technique: "T1037.002",
                  severity: .medium),
        // MDM installs profiles routinely on managed Macs.
        Indicator(id: uuid(54), name: "Configuration profile installed",
                  description: "Installed or staged a configuration profile, which can set a Mac's proxy, DNS and "
                    + "certificates.",
                  symbol: "gear.badge.checkmark", color: .blue, predicate: configurationProfilePredicate,
                  tactic: .defenseEvasion, technique: "T1553.004",
                  severity: .medium),
        Indicator(id: uuid(55), name: "Folder Action attached",
                  description: "Attached a Folder Action, a script that runs when a folder changes.",
                  symbol: "folder.badge.gearshape", color: .purple, predicate: folderActionPredicate,
                  tactic: .persistence, technique: "T1546",
                  severity: .medium),
        // Some admin scripts check a password this way too.
        Indicator(id: uuid(56), name: "Password checked with dscl",
                  description: "Checked a password with dscl, as stealers do to confirm one a fake prompt captured.",
                  symbol: "key.viewfinder", color: .blue, predicate: passwordCheckPredicate,
                  tactic: .credentialAccess, technique: "T1056.002",
                  severity: .medium),
        Indicator(id: uuid(57), name: "TCC database modified",
                  description: "Wrote a TCC database without tccd, as malware does to grant itself privacy "
                    + "permissions.",
                  symbol: "hand.raised.slash", color: .red, predicate: tccDatabasePredicate,
                  tactic: .defenseEvasion, technique: "T1548.006",
                  severity: .medium),
        // Downloads, builds and virtual machines' disks write these often.
        Indicator(id: uuid(58), name: "Archive written",
                  description: "Wrote an archive or disk image, whatever its name, as malware does to stage what it "
                    + "collects.",
                  symbol: "doc.zipper", color: .teal, predicate: archiveWrittenPredicate,
                  tactic: .collection, technique: "T1560",
                  severity: .low),
        // Script Editor and osacompile write these often, and osascript saves a script's properties back into it.
        Indicator(id: uuid(59), name: "AppleScript written",
                  description: "Wrote a compiled AppleScript or JXA script, or an osascript #! script, whatever its "
                    + "name.",
                  symbol: "applescript", color: .purple, predicate: appleScriptWrittenPredicate,
                  tactic: .execution, technique: "T1059.002",
                  severity: .low),
        // Code built on the Mac, such as Homebrew's or Xcode's, is adhoc signed too.
        Indicator(id: uuid(60), name: "Unsigned code resolved a name",
                  description: "An adhoc signed or unsigned process looked up a name, as an implant does before it "
                    + "calls home.",
                  symbol: "network", color: .blue, predicate: unsignedResolverPredicate,
                  tactic: .commandAndControl, technique: "T1071.004",
                  severity: .low),
        Indicator(id: uuid(16), name: "Elevated to root",
                  description: "Ran as root for a user who isn't, as sudo and setuid programs do.",
                  symbol: "key.radiowaves.forward.fill", color: .orange,
                  predicate: type("EXEC") + " AND event.exec.target.euid == 0 AND event.exec.target.ruid != 0",
                  tables: [.dot, .symbol],
                  tactic: .privilegeEscalation, technique: "T1548",
                  severity: .low),
        Indicator(id: uuid(27), name: "Remote thread created",
                  description: "Created a thread in another process, as code injection does.",
                  symbol: "exclamationmark.triangle.fill", color: .red, predicate: type("REMOTE_THREAD_CREATE"),
                  tables: [.dot, .symbol, .label],
                  tactic: .defenseEvasion, technique: "T1055",
                  severity: .medium),
        Indicator(id: uuid(30), name: "Task port retrieved",
                  description: "Got another process's task port, which can read and write its memory.",
                  symbol: "exclamationmark.triangle.fill", color: .orange, predicate: type("GET_TASK"),
                  tables: [.dot, .symbol, .label],
                  tactic: .defenseEvasion, technique: "T1055",
                  severity: .low),
        Indicator(id: uuid(29), name: "Process traced",
                  description: "Attached to another process with ptrace, as a debugger or an injector does.",
                  symbol: "exclamationmark.triangle.fill", color: .orange, predicate: type("TRACE"),
                  tables: [.dot, .symbol, .label],
                  tactic: .defenseEvasion, technique: "T1055.008",
                  severity: .low),
        Indicator(id: uuid(28), name: "Code signature invalidated",
                  description: "A process ran code that doesn't match its signature, so macOS invalidated it.",
                  symbol: "exclamationmark.triangle.fill", color: .red, predicate: type("CS_INVALIDATED"),
                  tables: [.dot, .symbol, .label],
                  tactic: .defenseEvasion, technique: "T1055",
                  severity: .low),
        Indicator(id: uuid(26), name: "HID device opened",
                  description: "Opened a keyboard or other input device's driver, as a keylogger does.",
                  symbol: "keyboard", color: .orange,
                  predicate: type("IOKIT_OPEN")
                    + #" AND event.iokit_open.user_client_class CONTAINS "IOHIDLibUserClient""#,
                  tables: [.dot, .symbol, .label],
                  tactic: .collection, technique: "T1056.001",
                  severity: .low),
        Indicator(id: uuid(25), name: "Background item removed",
                  description: "Removed a background item, so it no longer runs at login.",
                  symbol: "gearshape.2", color: .orange, predicate: type("BTM_LAUNCH_ITEM_REMOVE"),
                  tables: [.dot, .label],
                  tactic: .defenseEvasion, technique: "T1070",
                  severity: .low),
        // backgroundtaskmanagementd replaces the database whenever a background item changes, so this is context.
        Indicator(id: uuid(24), name: "BTM database modified",
                  description: "Replaced Background Task Management's database, which records login items, launch "
                    + "agents and launch daemons.",
                  symbol: "exclamationmark.triangle.fill", color: .orange,
                  predicate: type("RENAME")
                    + #" AND target_path BEGINSWITH "/private/var/db/com.apple.backgroundtaskmanagement/""#,
                  tables: [.dot, .symbol, .label],
                  tactic: .persistence, technique: "T1547.015",
                  severity: .low),
    ]
}
