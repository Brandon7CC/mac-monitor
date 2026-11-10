//
//  IndicatorTests+Cases.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Cases
/// The records each shipped indicator and built-in mark matches, and the ones close to them it doesn't. One table
/// serves every test that needs an indicator to hit and to miss: what each default matches, what each mark matches,
/// and the matcher's differential, which lays each record over an event of the synthetic corpus.
extension IndicatorTests {
    /// - Returns: A case or more for every default: these, then the persistence defaults' (``persistenceCases()``).
    func defaultCases() -> [Case] {
        /// - Parameters:
        ///   - target: The exec's target.
        ///   - exec: The rest of the exec.
        /// - Returns: An exec's record.
        func exec(_ target: [String: Any], _ exec: [String: Any] = [:]) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "event": ["exec": exec.merging(["target": target]) { $1 }]]
        }
        /// - Parameter path: The executable's path.
        /// - Returns: An exec's record of it, named as its path ends, as the store names it.
        func tool(_ path: String) -> NSDictionary {
            exec(["executable": ["path": path, "name": (path as NSString).lastPathComponent]])
        }
        /// - Parameters:
        ///   - path: The file opened.
        ///   - executable: The path of the process that opened it.
        /// - Returns: An open's record.
        func open(_ path: String, by executable: String) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_OPEN", "target_path": path,
             "process": ["executable": ["path": executable]]]
        }
        /// - Parameter driver: The driver's bundle ID, or `NSNull`.
        /// - Returns: An IOKit open's record.
        func iokitOpen(driver: Any) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN",
             "event": ["iokit_open": ["user_client_class": "IOUserClient", "driver_bundle_id": driver]]]
        }
        /// - Parameters:
        ///   - path: The file closed.
        ///   - modified: Whether it was written.
        /// - Returns: A close's record.
        func close(_ path: String, modified: Bool) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_CLOSE", "target_path": path,
             "event": ["close": ["modified": modified]]]
        }
        /// - Parameter path: The new path.
        /// - Returns: A rename's record.
        func rename(to path: String) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_RENAME", "target_path": path]
        }
        /// - Parameter type: The Mach-O type written, or `NSNull`.
        /// - Returns: A close's record of a file written.
        func machO(_ type: Any) -> NSDictionary {
            ["es_event_type": "ES_EVENT_TYPE_NOTIFY_CLOSE", "target_path": "/tmp/update",
             "event": ["close": ["modified": true, "mach_o_type": type]]]
        }
        let agent = "/Users/a/Library/LaunchAgents/com.example.agent.plist"
        let mmap = "ES_EVENT_TYPE_NOTIFY_MMAP"
        let login = "/Users/a/Library/Keychains/login.keychain-db"
        let detected = "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED"
        let remediated = "ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED"
        let cases: [Case] = [
            ("Reflective loading",
             ["es_event_type": mmap, "target_path": "/private/var/folders/T/NSCreateObjectFileImageFromMemory-cgAR"],
             ["es_event_type": mmap, "target_path": "/tmp/NSCreateObjectFileImageFromMemory.txt"]),
            ("Quarantine removed",
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR",
              "event": ["deleteextattr": ["extattr": "com.apple.quarantine"]]],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR",
              "event": ["deleteextattr": ["extattr": "com.apple.lastuseddate#PS"]]]),
            ("AppleScript / JXA",
             ["es_event_type": mmap, "target_path": "/System/Library/ScriptingAdditions/StandardAdditions.osax/x"],
             ["es_event_type": mmap, "target_path": "/usr/lib/libSystem.B.dylib"]),
            ("Keychain opened", open(login, by: "/tmp/stealer"), open("/Users/a/Library/Keychain.txt", by: "/tmp/a")),
            ("Keychain opened", open("/Library/Keychains/System.keychain", by: "/usr/bin/security"),
             open(login, by: "/usr/sbin/securityd")),
            ("Keychain opened", open(login, by: "/Applications/secd.app/Contents/MacOS/secd"),
             open("/System/Library/Keychains/SystemRootCertificates.keychain", by: "/tmp/a")),
            ("Login",
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN", "event": ["openssh_login": ["success": false]]],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT"]),
            ("New executable", exec([:], ["executable_age_ms": 4]), exec([:], ["executable_age_ms": 1_000])),
            ("Adhoc signed", exec(["codesigning_type": "ADHOC", "signing_id": "a.out"]),
             exec(["codesigning_type": "DEVELOPER_ID", "signing_id": "com.example.app"])),
            ("Unsigned", exec(["codesigning_type": "UNSIGNED", "signing_id": "Unknown", "is_adhoc_signed": false]),
             exec(["codesigning_type": "ADHOC", "signing_id": "a.out"])),
            ("Ran a script", exec([:], ["script_content": "echo hi"]), exec([:], ["script_content": ""])),
            ("Download tool", tool("/usr/bin/curl"), tool("/usr/local/bin/curly")),
            ("Non-Apple driver opened", iokitOpen(driver: "com.example.driver"),
             iokitOpen(driver: "com.apple.iokit.IOSurface")),
            ("Non-Apple driver opened", iokitOpen(driver: "com.applesauce.driver"), iokitOpen(driver: NSNull())),
            ("Plist modified", close(agent, modified: true), close(agent, modified: false)),
            ("Plist modified", rename(to: agent), rename(to: "/Users/a/Library/LaunchAgents/notes.txt")),
            ("Plist modified", close("/Users/a/Library/Preferences/com.example.app.PLIST", modified: true),
             close("/Users/a/Library/Preferences/com.example.plist.bak", modified: true)),
            ("Mach-O written", machO("MH_EXECUTE"), machO("MH_OBJECT")),
            ("Mach-O written", machO("MH_DYLIB"), machO(NSNull())),
            ("Mach-O written", machO("MH_BUNDLE"),
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_MMAP", "event": ["mmap": ["mach_o_type": "MH_DYLIB"]]]),
            ("Background item added", ["es_event_type": "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD"],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE"]),
            ("XProtect detection", ["es_event_type": detected],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE"]),
            ("XProtect detection", ["es_event_type": remediated],
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD"]),
        ]
        let names = Set(Indicator.defaults.map(\.name))
        let replacedMarks = labelCases().filter { names.contains($0.0) }
        let more: [Case] = passwordCheckCases(exec) + tccDatabaseCases() + archiveCases() + appleScriptCases()
        return (cases + more + resolverCases() + persistenceCases() + replacedMarks).map(Self.withPayloads)
    }

    /// - Parameter exec: Makes an exec's record from its target and the rest of it.
    /// - Returns: Password checked with dscl's cases. dscl on macOS 27.2 checks a password with `authonly`, `auth` or
    ///   its alias `su`, each with or without a dash, and refuses `-AUTHONLY`, `--authonly`, `-authonlyx`, `-AUTH`,
    ///   `-SU` and `-authx`, so none of those is a check.
    private func passwordCheckCases(_ exec: ([String: Any], [String: Any]) -> NSDictionary) -> [Case] {
        let name = "Password checked with dscl"
        /// - Parameters:
        ///   - commandLine: Its command line.
        ///   - path: The executable's path.
        /// - Returns: An exec's record of Apple's dscl, wherever it is.
        func dscl(_ commandLine: String, at path: String = "/usr/bin/dscl") -> NSDictionary {
            exec(["executable": ["path": path, "name": (path as NSString).lastPathComponent],
                  "signing_id": "com.apple.dscl"], ["command_line": commandLine])
        }
        let shell = exec(["executable": ["path": "/bin/zsh", "name": "zsh"]],
                         ["command_line": "zsh -c dscl . -authonly marcus pw"])
        return [
            (name, dscl("/usr/bin/dscl /Local/Default -authonly marcus pw"),
             dscl("dscl /Search -read /Users/marcus UniqueID")),
            (name, dscl("dscl . authonly marcus pw"), dscl("dscl . -authonlyx marcus pw")),
            (name, dscl("dscl . -authonly"), dscl("dscl . -read /Users/marcus-authonly")),
            (name, dscl("dscl . -authonly marcus pw"), dscl("dscl . -AUTHONLY marcus pw")),
            (name, dscl("dscl . -authonly marcus pw"), dscl("dscl . --authonly marcus pw")),
            (name, dscl("dscl . -auth marcus pw"), dscl("dscl . -authx marcus pw")),
            (name, dscl("dscl . auth marcus pw"), dscl("dscl . -AUTH marcus pw")),
            (name, dscl("dscl . -su marcus pw"), dscl("dscl . -SU marcus pw")),
            (name, dscl("dscl . su"), dscl("dscl . -read /Users/su-marcus")),
            /// The shell that starts dscl has the check in its arguments, but isn't dscl.
            (name, dscl("dscl . -authonly marcus pw"), shell),
            /// An unmodified copy of dscl elsewhere is killed by macOS's launch constraints, but one re-signed ad hoc
            /// checks passwords, so a copy that keeps dscl's name counts. A renamed copy isn't caught.
            (name, dscl("dscl . -authonly marcus pw", at: "/private/tmp/dscl"),
             dscl("ds . -authonly marcus pw", at: "/private/tmp/ds")),
        ]
    }

    /// - Returns: TCC database modified's cases: a modified close of, a rename onto or a hard link at a TCC database
    ///   or a file beside it, in the system's, root's or a home folder's TCC folder, or a rename onto that folder, by
    ///   anything but tccd at its path, signed as itself and a platform binary. A create, an unmodified close and
    ///   look-alike paths aren't writes.
    private func tccDatabaseCases() -> [Case] {
        let name = "TCC database modified"
        let system = "/Library/Application Support/com.apple.TCC/"
        let home = "/Users/a" + system
        let tccd = "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"
        /// - Parameters:
        ///   - type: The event type, without `ES_EVENT_TYPE_NOTIFY_`.
        ///   - path: Its target path.
        ///   - executable: The path of the process that caused it.
        ///   - signingID: That process's signing ID.
        ///   - platform: Is that process a platform binary?
        ///   - modified: For a close, was the file written?
        /// - Returns: A file event's record.
        func file(_ type: String, _ path: String, by executable: String = "/usr/bin/sqlite3",
                  signingID: String = "com.apple.sqlite3", platform: Bool = true,
                  modified: Bool = true) -> NSDictionary {
            let record = NSMutableDictionary(dictionary: [
                "es_event_type": "ES_EVENT_TYPE_NOTIFY_\(type)", "target_path": path,
                "process": ["executable": ["path": executable, "name": (executable as NSString).lastPathComponent],
                            "signing_id": signingID, "is_platform_binary": platform]])
            if type == "CLOSE" { record["event"] = ["close": ["modified": modified]] }
            return record
        }
        return [
            (name, file("CLOSE", system + "TCC.db"),
             file("CLOSE", system + "TCC.db", by: tccd, signingID: "com.apple.tccd")),
            (name, file("CLOSE", home + "TCC.db-wal"), file("CLOSE", home + "TCC.db", modified: false)),
            (name, file("RENAME", home + "TCC.db"),
             file("RENAME", "/Users/a/Library/Application Support/com.apple.TCC.bak/TCC.db")),
            (name, file("LINK", system + "TCC.db-journal"), file("CREATE", system + "TCC.db-shm")),
            (name, file("CLOSE", "/private/var/root" + system + "TCC.db-shm"), file("CLOSE", home + "TCC.db.backup")),
            (name, file("RENAME", home + "tcc.DB"), file("CLOSE", "/Users/a/Backups/Users/a" + system + "TCC.db")),
            (name, file("CLOSE", home + "TCC.db-journal"),
             file("CLOSE", "/Users/Library/Application Support/com.apple.TCC/TCC.db")),
            (name, file("CLOSE", system + "TCC.db-shm"), file("CLOSE", "/Volumes/Mac" + system + "TCC.db")),
            (name, file("CLOSE", system + "TCC.db"), file("CLOSE", system + "REG.db")),
            /// A copy of tccd anywhere else, or anything else at its path, isn't tccd.
            (name, file("CLOSE", system + "TCC.db", by: "/private/tmp/tccd", signingID: "com.apple.tccd"),
             file("RENAME", system + "TCC.db", by: tccd, signingID: "com.apple.tccd")),
            (name, file("CLOSE", home + "TCC.db", by: tccd, signingID: "tccd", platform: false),
             file("LINK", home + "TCC.db-wal", by: tccd, signingID: "com.apple.tccd")),
            (name, file("CLOSE", home + "TCC.db", by: tccd, signingID: "com.apple.tccd", platform: false),
             file("CLOSE", home + "TCC.db-shm", by: tccd, signingID: "com.apple.tccd")),
            (name, file("CLOSE", system + "TCC.db", by: tccd, signingID: "com.example.tccd"),
             file("CLOSE", system + "TCC.db-wal", by: tccd, signingID: "com.apple.tccd")),
            /// A folder renamed onto a TCC folder swaps in a whole database staged elsewhere.
            (name, file("RENAME", String(home.dropLast())),
             file("RENAME", "/Users/a/Library/Application Support/com.apple.TCC.bak")),
            (name, file("RENAME", "/private/var/root" + system.dropLast()),
             file("RENAME", String(system.dropLast()), by: tccd, signingID: "com.apple.tccd")),
            (name, file("RENAME", String(system.dropLast())),
             file("CLOSE", String(home.dropLast()))),
            (name, file("RENAME", "/Users/a/Library/Application Support/com.apple.tcc"),
             file("RENAME", "/Users/a/Backups/Users/a" + system.dropLast())),
        ]
    }

    /// - Returns: Archive written's cases: a modified close of each archive and disk image type a file's content is
    ///   named by, whatever the file's name, by anything but macOS's own content writers. A file named `.zip` that
    ///   isn't one, an Office, OpenDocument or EPUB document, an unmodified close, a static library, an mmap of an
    ///   archive, a write by backupd or fseventsd, and a rotated system log aren't.
    private func archiveCases() -> [Case] {
        let name = "Archive written"
        let events = "/System/Volumes/Data/.fseventsd/000000000215d94c"
        let rotated = "/private/var/log/system.log.0.gz", gzip = "org.gnu.gnu-zip-archive"
        let others = ["public.plain-text", "public.archive", "public.data", "com.apple.mach-o-dylib", "replaced",
                      "public.zip", "public.zip-archive.x", "public.disk-image", "public.cpio-archive",
                      "com.apple.disk-image-udif-segment", "public.iso-image", "com.apple.disk-image-cdr",
                      "com.apple.disk-image-raw.x"]
        let types = ["public.zip-archive", "com.apple.xar-archive", "org.gnu.gnu-zip-archive", "public.bzip2-archive",
                     "org.tukaani.xz-archive", "org.7-zip.7-zip-archive", "public.tar-archive", "com.apple.archive",
                     "com.apple.disk-image-udif", "com.apple.disk-image-raw", "com.apple.disk-image-sparse",
                     "com.apple.disk-image-sparse-bundle", "com.apple.disk-image"]
        return zip(types, others).map { (name, typedClose($0), typedClose($1)) } + [
            (name, typedClose("public.zip-archive", at: "/Users/a/notes.txt"),
             typedClose("public.plain-text", at: "/Users/a/notes.zip")),
            (name, typedClose("public.zip-archive", at: "/Users/a/report.docx"),
             typedClose("org.openxmlformats.openxml", at: "/Users/a/report.docx")),
            (name, typedClose("public.zip-archive", at: "/Users/a/book.epub"),
             typedClose("org.idpf.epub-container", at: "/Users/a/book.epub")),
            (name, typedClose("public.zip-archive", at: "/Users/a/report.odt"),
             typedClose("org.oasis-open.opendocument", at: "/Users/a/report.odt")),
            (name, typedClose("com.apple.disk-image-udif", at: "/Users/a/Downloads/Installer.dmg"),
             typedClose("com.apple.disk-image-udif", at: "/Users/a/Downloads/Installer.dmg", modified: false)),
            (name, typedClose("public.tar-archive"), typedClose(NSNull(), at: "/Users/a/loot.tar.gz")),
            (name, typedClose("org.gnu.gnu-zip-archive", signingID: "com.apple.backupd", platform: false),
             typedClose("org.gnu.gnu-zip-archive", signingID: "com.apple.backupd")),
            (name, typedClose("com.apple.archive", signingID: "com.example.backupd"),
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_MMAP", "target_path": "/Users/a/x.zip",
              "event": ["mmap": ["file_type": "public.zip-archive"]]] as NSDictionary),
            (name, typedClose("org.gnu.gnu-zip-archive", at: events, signingID: "com.apple.fseventsd", platform: false),
             typedClose("org.gnu.gnu-zip-archive", at: events, signingID: "com.apple.fseventsd")),
            (name, typedClose(gzip, at: rotated, signingID: "com.apple.aslmanager", platform: false),
             typedClose(gzip, at: rotated, signingID: "com.apple.aslmanager")),
            (name, typedClose("public.zip-archive", at: "/private/var/log/loot.zip"),
             typedClose(gzip, at: rotated, signingID: "com.apple.gzip")),
        ]
    }

    /// - Returns: AppleScript written's cases: a modified close of a file whose content is a compiled AppleScript or
    ///   JXA script, whatever its name, as a `.scpt` or an applet's `main.scpt`, or text whose `#!` line names
    ///   osascript, by osacompile, Script Editor, cp or anything but macOS's own content writers. Text named `.scpt`
    ///   or `.applescript` without a `#!` line, a JXA text script, an unmodified close, an mmap of a compiled script,
    ///   a write by backupd, or by Spotlight caching what it indexed, and a file whose type wasn't read aren't.
    private func appleScriptCases() -> [Case] {
        let name = "AppleScript written"
        let script = "com.apple.applescript.script"
        let applet = "/Users/a/Applications/Login.app/Contents/Resources/Scripts/main.scpt"
        let cache = "/System/Volumes/Data/.Spotlight-V100/Store-V2/0/Cache/0000/0000/0148/21531841.txt"
        let index = "/Users/a/Library/Metadata/CoreSpotlight/index.spotlightV3/Cache/1/a.txt"
        let text = "com.apple.applescript.text"
        return [
            (name, typedClose(script, at: "/Users/a/Library/Scripts/run.scpt", signingID: "com.apple.osacompile"),
             typedClose("public.plain-text", at: "/Users/a/Library/Scripts/run.scpt")),
            (name, typedClose(script, at: "/private/tmp/notes.txt", signingID: "com.apple.osascript"),
             typedClose(script, at: "/private/tmp/run.scpt", modified: false)),
            (name, typedClose(script, at: applet, signingID: "com.apple.ScriptEditor2"),
             ["es_event_type": "ES_EVENT_TYPE_NOTIFY_MMAP", "target_path": applet,
              "event": ["mmap": ["file_type": script]]] as NSDictionary),
            (name, typedClose(script, signingID: "com.apple.backupd", platform: false),
             typedClose(script, signingID: "com.apple.backupd")),
            (name, typedClose(script, at: "/Users/a/Library/Scripts/Folder Action Scripts/watch.scpt"),
             typedClose(NSNull(), at: "/Users/a/Library/Scripts/Folder Action Scripts/watch.scpt")),
            (name, typedClose("com.apple.applescript.text", at: "/Users/a/.local/bin/sync", signingID: "com.apple.cp"),
             typedClose("public.plain-text", at: "/Users/a/run.applescript")),
            (name, typedClose(script, at: "/Users/a/jxa.scpt"),
             typedClose("com.netscape.javascript-source", at: "/Users/a/.local/bin/jxa")),
            (name, typedClose(text, at: cache, signingID: "com.apple.mds_stores", platform: false),
             typedClose(text, at: cache, signingID: "com.apple.mds_stores")),
            (name, typedClose(text, at: cache, signingID: "com.apple.mds"),
             typedClose(script, at: index, signingID: "com.apple.corespotlightd")),
            (name, typedClose(text, at: index, signingID: "com.apple.managedcorespotlightd", platform: false),
             typedClose(text, at: index, signingID: "com.apple.managedcorespotlightd")),
        ]
    }

    /// A modified close's record of a file whose content was named by a type, as the content indicators read it.
    ///
    /// - Parameters:
    ///   - type: The type its content is named by, or `NSNull`.
    ///   - path: The file closed.
    ///   - modified: Was it written?
    ///   - signingID: The signing ID of the process that closed it.
    ///   - platform: Is that process a platform binary?
    /// - Returns: A close's record.
    private func typedClose(_ type: Any, at path: String = "/Users/a/Downloads/payload", modified: Bool = true,
                            signingID: String = "com.apple.zip", platform: Bool = true) -> NSDictionary {
        ["es_event_type": "ES_EVENT_TYPE_NOTIFY_CLOSE", "target_path": path,
         "event": ["close": ["modified": modified, "file_type": type]],
         "process": ["signing_id": signingID, "is_platform_binary": platform]]
    }

    /// - Returns: A case or more for every built-in mark that isn't a default's twin, whose cases are the default's.
    func markCases() -> [Case] {
        let names = Set(Indicator.builtInMarks.map(\.name))
        return labelCases().filter { names.contains($0.0) }.map(Self.withPayloads)
    }

    /// - Parameter case: A case.
    /// - Returns: The same, each record with its type's payload (``NSDictionary/withPayload``).
    static func withPayloads(_ case: Case) -> Case {
        (`case`.0, `case`.1.withPayload, `case`.2.withPayload)
    }

    /// - Returns: A case or more for each event the labels marked before indicators: by a built-in mark, or by the
    ///   default that replaced one in 3.1.0, by its name.
    private func labelCases() -> [Case] {
        /// - Parameters:
        ///   - type: The event type, without `ES_EVENT_TYPE_NOTIFY_`.
        ///   - event: The event's fields, under its key, or none.
        ///   - path: Its target path, or none.
        /// - Returns: A record.
        func record(_ type: String, _ event: [String: Any] = [:], path: String? = nil) -> NSDictionary {
            let record = NSMutableDictionary(dictionary: ["es_event_type": "ES_EVENT_TYPE_NOTIFY_\(type)"])
            if !event.isEmpty { record["event"] = [type.lowercased(): event] }
            record["target_path"] = path
            return record
        }
        /// - Parameter target: The exec's target.
        /// - Returns: An exec's record.
        func exec(_ target: [String: Any]) -> NSDictionary { record("EXEC", ["target": target]) }
        /// - Parameters:
        ///   - path: The file created.
        ///   - quarantined: Whether it's quarantined.
        ///   - aware: Whether the process creating it is File Quarantine-aware.
        /// - Returns: A create's record.
        func create(_ path: String, quarantined: Int, aware: Bool = false) -> NSDictionary {
            let created = NSMutableDictionary(dictionary: record("CREATE", ["is_quarantined": quarantined], path: path))
            created["process"] = ["file_quarantine_type": aware ? "OPT_IN" : "DISABLED"]
            return created
        }
        /// - Parameters:
        ///   - path: The new path.
        ///   - quarantined: Whether it's quarantined.
        /// - Returns: A rename's record.
        func rename(_ path: String, quarantined: Int) -> NSDictionary {
            record("RENAME", ["is_quarantined": quarantined], path: path)
        }
        let reflective = "/private/var/folders/T/NSCreateObjectFileImageFromMemory-cgAR"
        let btm = "/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v9.btm"
        let typeOnly: [(String, String, String)] = [
            ("Background item added", "BTM_LAUNCH_ITEM_ADD", "BTM_LAUNCH_ITEM_REMOVE"),
            ("Background item removed", "BTM_LAUNCH_ITEM_REMOVE", "BTM_LAUNCH_ITEM_ADD"),
            ("XProtect detection", "XP_MALWARE_DETECTED", "GATEKEEPER_USER_OVERRIDE"),
            ("XProtect detection", "XP_MALWARE_REMEDIATED", "XPC_CONNECT"),
            ("Remote thread created", "REMOTE_THREAD_CREATE", "GET_TASK"),
            ("Code signature invalidated", "CS_INVALIDATED", "TRACE"),
            ("Process traced", "TRACE", "GET_TASK"),
            ("Task port retrieved", "GET_TASK", "TRACE"),
        ]
        let cases: [Case] = [
            ("File Quarantine-aware", exec(["file_quarantine_type": "OPT_IN"]),
             exec(["file_quarantine_type": "DISABLED"])),
            ("File Quarantine-aware process", exec(["file_quarantine_type": "FORCED"]),
             exec(["file_quarantine_type": "DISABLED"])),
            ("Root user", exec(["ruid": 0, "euid": 0]), exec(["ruid": 501, "euid": 0])),
            ("Elevated to root", exec(["ruid": 501, "euid": 0]), exec(["ruid": 0, "euid": 0])),
            ("Reflective loading", create(reflective, quarantined: 0),
             create("/tmp/NSCreateObjectFileImageFromMemory.txt", quarantined: 0)),
            ("Reflective loading", record("MMAP", path: reflective), record("MMAP", path: "/tmp/x.dylib")),
            ("Unquarantined file created", create("/Users/a/x", quarantined: 0, aware: true),
             create("/Users/a/x", quarantined: 1, aware: true)),
            ("Unquarantined file created", create("/Users/a/x", quarantined: 0, aware: true),
             create(reflective, quarantined: 0, aware: true)),
            ("Quarantined file", create("/Users/a/x", quarantined: 1), create("/Users/a/x", quarantined: 0)),
            ("AppleScript / JXA",
             record("MMAP", path: "/System/Library/Components/AppleScript.component/Contents/MacOS/AppleScript"),
             record("MMAP", path: "/usr/lib/libSystem.B.dylib")),
            ("Quarantined file renamed", rename("/Users/a/x", quarantined: 1), rename("/Users/a/x", quarantined: 0)),
            ("Unquarantined app bundle", rename("/Applications/X.app", quarantined: 0),
             rename("/Applications/X.app", quarantined: 1)),
            ("BTM database modified", rename(btm, quarantined: 0), rename(btm, quarantined: 1)),
            ("BTM database modified", rename(btm, quarantined: 0), rename("/Users/a/x", quarantined: 0)),
            ("Quarantine removed", record("DELETEEXTATTR", ["extattr": "com.apple.quarantine"]),
             record("DELETEEXTATTR", ["extattr": "com.apple.lastuseddate#PS"])),
            ("Login Item written",
             record("WRITE", path: "/private/var/db/com.apple.backgroundtaskmanagementd/x"),
             record("WRITE", path: "/tmp/x")),
            ("HID device opened", record("IOKIT_OPEN", ["user_client_class": "IOHIDLibUserClient"]),
             record("IOKIT_OPEN", ["user_client_class": "IOUserClient"])),
            ("Non-zero exit", record("EXIT", ["stat": 256]), record("EXIT", ["stat": 0])),
        ]
        return cases + typeOnly.map { ($0.0, record($0.1), record($0.2)) }
    }
}


// MARK: - Payloads
extension NSDictionary {
    /// The record, with its type's payload key under `event` as every record has, an empty object when it gives the
    /// payload no fields, so a payload test (`event.btm_launch_item_add != nil`) reads it as it reads a real record.
    var withPayload: NSDictionary {
        let prefix = "ES_EVENT_TYPE_NOTIFY_"
        guard let type = self["es_event_type"] as? String, type.hasPrefix(prefix) else { return self }
        let key = type.dropFirst(prefix.count).lowercased()
        var event = self["event"] as? [String: Any] ?? [:]
        guard event[key] == nil else { return self }
        event[key] = [String: Any]()
        let record = NSMutableDictionary(dictionary: self)
        record["event"] = event
        return record
    }
}
