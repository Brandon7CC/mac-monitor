//
//  DefaultIndicatorSource+Predicates.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Default predicates
extension Indicator {
    /// The predicate a write of a shell's startup file matches: a modified close, a create, a hard link or a rename
    /// into place of a file zsh, bash, csh or fish runs as it starts, in a home folder or in `/private/etc`, or of a
    /// compiled `.zwc` zsh runs instead, or of a `PATH` entry. Names are compared ignoring case, as APFS opens them.
    /// `/private/var/folders` is left out, where VS Code's terminal copies its own startup files for every terminal.
    static let shellStartupPredicate = written(or: "CREATE", "RENAME", "LINK")
        + #" AND NOT target_path BEGINSWITH "/private/var/folders" AND ("#
        + alternatives("target_path ENDSWITH[c]", zshStartupFiles.flatMap { ["/.\($0)", "/.\($0).zwc"] }
            + ["/.bash_profile", "/.bashrc", "/.bash_login", "/.bash_logout", "/.profile", "/.cshrc", "/.tcshrc",
               "/.login", "/.logout"])
        + #" OR target_path CONTAINS[c] "/.zkbd" OR (target_path CONTAINS[c] "/.config/fish" "#
        + #"AND target_path ENDSWITH[c] ".fish") OR (target_path BEGINSWITH "/private/etc" AND ("#
        + alternatives("target_path ENDSWITH[c]", zshStartupFiles.filter { $0 != "zshrc" }.map { "/" + $0 }
            + ["/profile", ".zwc"])
        + " OR " + alternatives("target_path CONTAINS[c]", ["/zshrc", "/bashrc", "/csh.", "/paths"]) + ")))"

    /// The predicate a scheduled job matches: a cron table written, created, linked or renamed into
    /// `/private/var/at/tabs` or as `/private/etc/crontab`, an at job created in `/private/var/at/jobs`, other than
    /// at's own sequence and lock files and the folder itself, or launchctl turning on atrun, which runs at jobs.
    static let scheduledJobPredicate = "(" + written(or: "CREATE", "RENAME", "LINK")
        + #" AND (target_path BEGINSWITH[c] "/private/var/at/tabs" OR (target_path BEGINSWITH[c] "/private/etc" "#
        + #"AND target_path ENDSWITH[c] "/crontab"))) OR ("# + type("CREATE", "RENAME", "LINK")
        + #" AND target_path BEGINSWITH[c] "/private/var/at/jobs" AND NOT "#
        + anyOf("target_path ENDSWITH[c]", ["/.SEQ", "/.lockfile"]) + " AND NOT (" + type("CREATE")
        + #" AND target_path ENDSWITH[c] "/jobs")) OR ("# + type("EXEC") + " AND " + launchctl
        + #" AND event.exec.command_line CONTAINS "com.apple.atrun" AND "#
        + anyOf("event.exec.command_line CONTAINS", [" enable ", " load ", " bootstrap ", " kickstart "]) + ")"

    /// The predicate a change to authentication matches: sudo's configuration, a PAM stack or a module in
    /// `/usr/local/lib/pam` written or put in place, other than an editor's or visudo's temporary file, which neither
    /// reads; an authorization plugin or OpenDirectory module added, the executable inside one replaced, or a staged
    /// folder of them renamed over the plugins or modules folder, which ship empty, with either separator a rename's
    /// new path has had; the authorization database written by anything but authd; or a petition for a right that adds
    /// or modifies rights. A petition's context lists every right it asks for, as in
    /// `[right1,right2] petitioner → instigator`.
    static let authenticationModifiedPredicate = "(" + written(or: "CREATE", "RENAME", "LINK") + " AND "
        + anyOf("target_path BEGINSWITH[c]", ["/private/etc/sudo", "/private/etc/pam.d", "/usr/local/lib/pam"])
        + " AND NOT " + anyOf("target_path ENDSWITH", [".tmp", ".swp", "~"]) + ") OR (" + type("CREATE", "RENAME")
        + #" AND ((target_path BEGINSWITH "\#(authorizationPlugins)" AND target_path ENDSWITH[c] ".bundle") "#
        + #"OR (target_path BEGINSWITH "\#(directoryModules)" AND target_path ENDSWITH[c] ".xpc"))) OR ("#
        + type("RENAME") + " AND "
        + anyOf("target_path LIKE[c]", ["/Library/Security*/SecurityAgentPlugins", "/Library/OpenDirectory*/Modules"])
        + ") OR ("
        + written(or: "RENAME") + " AND " + anyOf("target_path BEGINSWITH", [authorizationPlugins, directoryModules])
        + #" AND target_path CONTAINS "/Contents/MacOS") OR ("# + type("CLOSE")
        + #" AND event.close.modified == YES AND target_path BEGINSWITH "/private/var/db/auth.db" "#
        + #"AND NOT process.executable.path == "\#(authd)") OR ("# + type("AUTHORIZATION_PETITION") + " AND ("
        + alternatives("context BEGINSWITH", ["[config.add.", "[config.modify."]) + " OR "
        + alternatives("context CONTAINS", [",config.add.", ",config.modify."]) + "))"

    /// The predicate a change to SSH access matches: an `authorized_keys` file or a `.ssh/rc` script, or sshd's
    /// `sshrc`, configuration or the crypto configuration it includes, written or put in place, or a whole `.ssh`
    /// folder renamed into place. Names are compared ignoring case, as APFS opens them. `/Volumes` is left out, where
    /// a backup copies a home folder.
    static let sshAccessPredicate = "((" + written(or: "CREATE", "RENAME", "LINK")
        + #" AND ((target_path CONTAINS[c] "/.ssh" AND "#
        + anyOf("target_path ENDSWITH[c]", ["/authorized_keys", "/authorized_keys2", "/rc"])
        + #") OR (target_path CONTAINS[c] "/private/etc/ssh" AND (target_path ENDSWITH[c] "/sshrc" "#
        + #"OR target_path CONTAINS[c] "/sshd_config" OR target_path CONTAINS[c] "/crypto")))) OR ("#
        + type("RENAME") + #" AND target_path ENDSWITH[c] "/.ssh")) AND NOT target_path BEGINSWITH "/Volumes/""#

    /// The predicate a sideloaded Chromium extension matches: a `.json` in an External Extensions folder, or the folder
    /// itself, written, linked or renamed into place, or an app's executable started with `-load-extension=`, in either
    /// of the switch's spellings, by anything but a test harness. The whole command line is read, not the first 200
    /// characters an exec's context has. The switch comes before the app's path: few execs have it and most apps'
    /// have the path, and the index looks an exec's rule up by the first of the two.
    static let browserExtensionPredicate = "(" + written(or: "RENAME", "LINK")
        + #" AND target_path CONTAINS[c] "/External Extensions" AND (target_path ENDSWITH[c] ".json" "#
        + #"OR target_path ENDSWITH[c] "/External Extensions")) OR ("# + type("EXEC")
        + #" AND event.exec.command_line CONTAINS "-load-extension=" "#
        + #"AND event.exec.target.executable.path CONTAINS ".app/Contents/MacOS/" AND NOT process.executable.name IN "#
        + #"{"node", "Cypress", "chromedriver", "msedgedriver"})"#

    /// The predicate a launchd job loaded from outside the folders Background Task Management watches matches:
    /// launchctl, by name or signature, bootstrapping, loading or submitting a job. Its subcommands are case-sensitive.
    /// A bootstrap or load of one plist directly in `/Library/LaunchAgents`, `/Library/LaunchDaemons` or a home
    /// folder's `Library/LaunchAgents` is left out, written as installers write it (`//Library/...`) too, when it's the
    /// last argument and only a flag or a domain comes before it. One that also names another path, relative or not,
    /// before or after it, a subfolder or `/../` still counts, as does any submit, which runs a program, not a plist,
    /// and a path with a space in it.
    static let launchJobLoadedPredicate = type("EXEC") + " AND " + launchctl + " AND "
        + anyOf("event.exec.command_line CONTAINS", [" bootstrap ", " load ", " submit "])
        + #" AND NOT (NOT event.exec.command_line CONTAINS " submit " AND ("#
        + anyOf("event.exec.command_line CONTAINS[c]", [" /Library/LaunchAgents/", " /Library/LaunchDaemons/",
                                                        " //Library/LaunchAgents/", " //Library/LaunchDaemons/"])
        + #" OR (event.exec.command_line LIKE[c] "* /Users/*/Library/LaunchAgents/*" "#
        + #"AND NOT event.exec.command_line LIKE[c] "* /Users/*/*/Library/*")) "#
        + #"AND NOT event.exec.command_line CONTAINS "/../" AND NOT event.exec.command_line LIKE "* /* /*" "#
        + #"AND NOT event.exec.command_line LIKE[c] "*/Library/Launch*/*/*" "#
        + #"AND event.exec.command_line ENDSWITH[c] ".plist" "#
        + #"AND NOT event.exec.command_line LIKE[c] "*.plist*.plist*" AND "# + launchctlArguments + ")"

    /// The comparisons a launchctl command line passes when it has three arguments at most and, with three, the
    /// second is a flag or a domain, as in `launchctl load -w <plist>` or `launchctl bootstrap gui/501 <plist>`, so
    /// nothing but the plist after it is a path. `LIKE`'s `*` matches spaces too, so the spaces are counted.
    static let launchctlArguments = #"NOT event.exec.command_line LIKE "* * * * *" "#
        + #"AND (NOT event.exec.command_line LIKE "* * * *" OR "#
        + anyOf("event.exec.command_line LIKE", ["* * -* *", "* bootstrap system *", "* bootstrap gui/* *",
                                                 "* bootstrap user/* *"]) + ")"

    /// The predicate an inserted dylib matches: an exec with `DYLD_INSERT_LIBRARIES` set, however it was started (by
    /// xpcproxy for a launchd job or an app, by a job's wrapper script, or by a shell), or launchctl setting it for
    /// later jobs. Xcode's own libraries, one or two from an Xcode app, or Guard Malloc alone, inserted into what Xcode
    /// built or ships, are left out. A list that also names any other library, or `/../`, still counts. The built-in
    /// mark that the event label and the process name draw is this indicator's twin (``dyldInsertion``).
    static let dylibInsertedPredicate = type("EXEC") + #" AND ((ANY event.exec.env BEGINSWITH "\#(dyldInsert)") "#
        + #"OR ("# + launchctl
        + #" AND event.exec.command_line CONTAINS " setenv " "#
        + #"AND event.exec.command_line CONTAINS "DYLD_INSERT_LIBRARIES")) "#
        + #"AND NOT ((event.exec.target.executable.path CONTAINS "/Build/Products/" "#
        + #"OR event.exec.target.executable.path BEGINSWITH "/Applications/Xcode") "#
        + #"AND NOT ANY event.exec.env LIKE "\#(dyldInsert)*/../*" AND "# + xcodeInsertions + ")"

    /// The comparisons an exec passes when `DYLD_INSERT_LIBRARIES` names only what Xcode inserts as it debugs: one or
    /// two libraries from an Xcode app's `Contents/Developer`, or Guard Malloc alone. The value is a colon-separated
    /// list, so the colons are counted. A library in a folder named as Xcode is, such as
    /// `/Applications/Xcode/X.app/Contents/Developer`, isn't one.
    static let xcodeInsertions: String = {
        let library = "/Applications/Xcode*.app/Contents/Developer/*"
        let lookalike = "/Applications/Xcode*/*.app/Contents/Developer/*"
        func inserts(_ pattern: String) -> String { #"ANY event.exec.env LIKE "\#(dyldInsert)\#(pattern)""# }
        return "((" + inserts(library) + " AND NOT " + inserts("*:*") + " AND NOT " + inserts(lookalike) + ") OR ("
            + inserts(library + ":" + library) + " AND NOT " + inserts("*:*:*") + " AND NOT "
            + inserts(lookalike + ":*") + " AND NOT " + inserts("*:" + lookalike) + ")"
            + #" OR ANY event.exec.env == "\#(dyldInsert)/usr/lib/libgmalloc.dylib")"#
    }()

    /// The predicate a plug-in installed matches: a screen saver, Spotlight importer, color picker, preference pane or
    /// input method created or renamed into `/Library` or a home folder's `Library`, an audio driver into
    /// `/Library/Audio/Plug-Ins/HAL`, which coreaudiod loads from, or one of those folders itself, as a staged folder
    /// renamed into place or a symlink makes it. Folder names are compared ignoring case. Plug-ins inside app bundles,
    /// and copies anywhere else, such as a backup, a DSTROOT, an installer's sandbox, or a package root or an Xcode
    /// archive in a home folder, are left out.
    static let pluginInstalledPredicate = type("CREATE", "RENAME")
        + #" AND NOT target_path CONTAINS[c] ".app/Contents/" AND NOT target_path LIKE[c] "/Users/*/*/Library/*" AND ("#
        + pluginFolders.map { folder, suffix in
            #"(target_path ENDSWITH[c] "\#(suffix)" AND (target_path BEGINSWITH[c] "/Library/\#(folder)" "#
                + #"OR target_path LIKE[c] "/Users/*/Library/\#(folder)*"))"#
        }.joined(separator: " OR ")
        + #" OR (target_path ENDSWITH[c] ".driver" AND target_path BEGINSWITH[c] "/Library/Audio/Plug-Ins/HAL") "#
        + #"OR ((target_path BEGINSWITH[c] "/Library" OR target_path LIKE[c] "/Users/*/Library*") AND "#
        + anyOf("target_path ENDSWITH[c]", pluginFolders.map { "/" + $0.folder })
        + #" AND NOT target_path LIKE[c] "*/Library/*/*"))"#

    /// The predicate a terminal startup command matches: a file written, linked or renamed into a home folder's
    /// iTerm2 `Scripts/AutoLaunch` folder, or as the `AutoLaunch.scpt` older iTerm builds run, other than the folder
    /// created empty and the Python runtime and caches a full-environment script keeps in its `iterm2env` and
    /// `__pycache__`; or an exec whose command line names Terminal's preferences and a profile's `CommandString`, or
    /// iTerm2's and a profile's `Command` (which `Custom Command` also has) or `Initial Text`, or imports either domain
    /// with `defaults import`. Domains are compared ignoring case, as `defaults` finds them; keys aren't. Command lines
    /// that read, export or remove preferences are left out.
    static let terminalStartupPredicate = "(" + written(or: "CREATE", "RENAME", "LINK") + " AND "
        + inHomeLibrary("Application Support/iTerm")
        + #" AND (target_path CONTAINS[c] "/iTerm2/Scripts/AutoLaunch" OR target_path ENDSWITH[c] "/AutoLaunch.scpt") "#
        + "AND NOT (" + type("CREATE") + #" AND target_path ENDSWITH[c] "/AutoLaunch") AND NOT "#
        + anyOf("target_path CONTAINS[c]", ["/iterm2env/", "/__pycache__/"]) + ") OR (" + type("EXEC")
        + #" AND ((event.exec.command_line CONTAINS[c] "com.apple.Terminal" AND "#
        + anyOf("event.exec.command_line CONTAINS", ["CommandString"] + defaultsImport)
        + #") OR (event.exec.command_line CONTAINS[c] "com.googlecode.iterm2" AND "#
        + anyOf("event.exec.command_line CONTAINS", ["Command", "Initial Text"] + defaultsImport) + ")) AND NOT "
        + anyOf("event.exec.command_line CONTAINS", preferenceReads) + ")"

    /// The predicate a login or logout hook matches: an exec whose command line names loginwindow's preferences and
    /// `LoginHook` or `LogoutHook`, as `defaults write`, PlistBuddy and plutil do, or imports the domain whole with
    /// `defaults import`, other than one that reads, exports or removes preferences; or root's
    /// `com.apple.loginwindow.plist` written, linked or renamed into place by anything but cfprefsd, which saves what
    /// `defaults write` asks for, whatever key it changes. Names are compared ignoring case. A harness that restores
    /// loginwindow's preferences with `defaults import` matches too, as one restoring Terminal's does.
    static let loginHookPredicate = "(" + type("EXEC")
        + #" AND event.exec.command_line CONTAINS[c] "com.apple.loginwindow" AND ("#
        + alternatives("event.exec.command_line CONTAINS[c]", ["LoginHook", "LogoutHook"]) + " OR "
        + alternatives("event.exec.command_line CONTAINS", defaultsImport) + ") AND NOT "
        + anyOf("event.exec.command_line CONTAINS", preferenceReads)
        + ") OR (" + written(or: "CREATE", "RENAME", "LINK")
        + #" AND target_path BEGINSWITH[c] "/private/var/root/Library/Preferences" "#
        + #"AND target_path ENDSWITH[c] "/com.apple.loginwindow.plist" "#
        + #"AND NOT process.executable.path == "\#(cfprefsd)")"#

    /// The predicate a configuration profile matches: a profile installed, or one created or renamed into
    /// `ProfilePurgatory`, where a profile someone opened waits for them to approve it in System Settings. The folder
    /// created empty is left out.
    static let configurationProfilePredicate = type("PROFILE_ADD") + " OR (" + type("CREATE", "RENAME")
        + #" AND target_path BEGINSWITH[c] "/private/var/db/ConfigurationProfiles/Store/ProfilePurgatory" AND NOT ("#
        + type("CREATE") + #" AND target_path ENDSWITH[c] "/ProfilePurgatory"))"#

    /// The predicate a Folder Action matches: a script written, linked or renamed into a home folder's
    /// `Scripts/Folder Action Scripts`, other than the folder created empty and Finder's `.DS_Store` in it, or a
    /// modified close or a rename of a home folder's `com.apple.FolderActionsDispatcher.plist`, as cfprefsd saves what
    /// System Events attaches.
    static let folderActionPredicate = "(" + written(or: "CREATE", "RENAME", "LINK") + " AND "
        + inHomeLibrary("Scripts/Folder Action Scripts") + " AND NOT (" + type("CREATE")
        + #" AND target_path ENDSWITH[c] "/Folder Action Scripts")) OR ("# + written(or: "RENAME")
        + #" AND target_path ENDSWITH[c] "/com.apple.FolderActionsDispatcher.plist" AND "#
        + homeLibraryPath("Preferences") + ")"

    /// The predicate a password check matches: an exec of a binary named `dscl` with one of its commands that checks
    /// a password, `authonly` or `auth` (whose alias is `su`), as one of its arguments. dscl takes a command with or
    /// without its dash, and only in lowercase, so `-AUTHONLY`, `--authonly` and `-authonlyx` aren't checks. The
    /// arguments are read from the command line, which joins them with spaces, so the word has a space before it and
    /// a space or the end after it, and a record's value with the word in it counts too. The name rather than the
    /// path is matched: macOS's launch constraints kill an unmodified copy of dscl run from another path, but a copy
    /// re-signed ad hoc runs and checks passwords, and keeps its name unless it's renamed.
    static let passwordCheckPredicate: String = {
        let commands = ["authonly", "auth", "su"].flatMap { ["-" + $0, $0] }
        return type("EXEC") + #" AND event.exec.target.executable.name == "dscl" AND ("#
            + alternatives("event.exec.command_line CONTAINS", commands.map { " " + $0 + " " }) + " OR "
            + alternatives("event.exec.command_line ENDSWITH", commands.map { " " + $0 }) + ")"
    }()

    /// The predicate a name resolved by unsigned code matches: an adhoc or unsigned process
    /// (``adhocOrUnsignedProcess``) connecting to the system resolver, by its socket, a root-owned one at exactly
    /// ``resolverSocket``, or by its XPC service, ``resolverService`` in the system domain. Any process can bind a
    /// socket named mDNSResponder elsewhere, or one at that path once it's gone, and a user's launchd domain can name
    /// a service as the system's does, so neither is the resolver. Each process connects once, however many names it
    /// resolves, and which name isn't known. The index looks the rule up by the exact path or service name, so every
    /// other connect costs it one lookup.
    static let unsignedResolverPredicate = "((" + type("UIPC_CONNECT")
        + #" AND target_path == "\#(resolverSocket)" AND event.uipc_connect.file.stat.st_uid == 0) OR ("#
        + type("XPC_CONNECT") + #" AND event.xpc_connect.service_name == "\#(resolverService)" "#
        + #"AND event.xpc_connect.service_domain_type_string == "SYSTEM")) AND "# + adhocOrUnsignedProcess

    /// The predicate a write of a TCC database matches: `TCC.db`, or the `-wal`, `-shm` or `-journal` file SQLite
    /// keeps beside it, in `/Library/Application Support/com.apple.TCC`, root's or a home folder's, written by anything
    /// but tccd. Of the file events Mac Monitor records by default, a modified close is a write in place, as SQLite and
    /// `cp` make, and a rename or a hard link puts another file in its place, as moving an edited copy back does. A
    /// rename onto the TCC folder itself swaps in a whole folder with an edited database staged elsewhere. A create is
    /// left out: SQLite creates the `-wal` and `-shm` as it opens the database, even to read it, and what's then
    /// written to them is a modified close. Unlink and write aren't recorded by default.
    ///
    /// Paths are matched whole, ignoring case, as APFS opens them: the file's or folder's name and the folders above
    /// it at the end, which the index looks up, then the system's or root's path exactly, or a folder in `/Users` and
    /// its `Library`, so a copy in `com.apple.TCC.bak`, a `TCC.db.backup` or a home folder's backup isn't one. tccd is
    /// the process at its path that's a platform binary signed as `com.apple.tccd`, so a copy of it anywhere else,
    /// named tccd or not, counts. Permission changes tccd makes are TCC modify events, not this.
    static let tccDatabasePredicate: String = {
        let folder = "/Library/Application Support/com.apple.TCC"
        let files = ["TCC.db", "TCC.db-wal", "TCC.db-shm", "TCC.db-journal"].map { folder + "/" + $0 }
        let paths = files + [folder]
        return "((" + written(or: "RENAME", "LINK") + " AND " + anyOf("target_path ENDSWITH[c]", files) + ") OR ("
            + type("RENAME") + #" AND target_path ENDSWITH[c] "\#(folder)")) AND ("#
            + alternatives("target_path LIKE[c]", paths + paths.map { "/private/var/root" + $0 }) + " OR ("
            + homeLibraryPath("Application Support/com.apple.TCC") + "))"
            + #" AND NOT (process.executable.path == "\#(tccd)" AND process.signing_id == "com.apple.tccd" "#
            + "AND process.is_platform_binary == YES)"
    }()

    /// The predicate an exec of adhoc signed code matches (``adhocTarget``). With Unsigned it's what Adhoc or unsigned
    /// was: the two never match the same exec, so each colors the label of its own, orange and red, as the label
    /// itself did before indicators could (``Indicator/TableMarks/label``).
    static let adhocSignedPredicate = type("EXEC") + " AND (" + adhocTarget + ")"

    /// The predicate an exec of unsigned code matches: code that isn't adhoc signed (``adhocTarget``) and either is
    /// typed `UNSIGNED`, as Mac Monitor types code with no signature and signed code whose signature is no longer
    /// valid, or has no signing ID.
    static let unsignedPredicate = type("EXEC") + #" AND (event.exec.target.codesigning_type == "UNSIGNED" "#
        + #"OR event.exec.target.signing_id == nil OR event.exec.target.signing_id IN {"", "Unknown"}) "#
        + "AND NOT (" + adhocTarget + ")"

    /// The predicate a write of a runnable Mach-O matches: a modified close of a file whose content is an executable,
    /// dylib or bundle. Only a modified close has a `mach_o_type`.
    static let machOWrittenPredicate = type("CLOSE")
        + #" AND event.close.mach_o_type IN {"MH_EXECUTE", "MH_DYLIB", "MH_BUNDLE"}"#

    /// The predicate a write of an archive or disk image matches: a modified close of a file whose content is one of
    /// ``archiveTypes``, whatever its name, by anything but one of macOS's own ``contentKeepers`` (Time Machine's
    /// backupd, fseventsd, which gzips each volume's file system event log, and Spotlight's index daemons), each its
    /// signing ID, a platform binary and not adhoc signed, and but macOS's disk image daemons writing a sparse
    /// bundle's bands, whose content is whatever blocks of the disk they hold, and but macOS's own programs rotating
    /// its system logs (``rotatedSystemLog``). Only a modified close has a `file_type`, read from the file's first
    /// 4 KB and, for data, a raw disk or a compressed stream, its last 512 bytes.
    static let archiveWrittenPredicate = contentWritten(archiveTypes, besides: [rotatedSystemLog])

    /// The predicate a write of AppleScript matches: a modified close of a file whose content is AppleScript's
    /// `FasdUAS` or JXA's `JsOsaDAS`, or text whose `#!` line names osascript, whatever its name, by anything but
    /// one of macOS's own ``contentKeepers`` (Time Machine's backupd, fseventsd, and Spotlight's index daemons, which
    /// cache the text they index, a script's among it), and but a sparse bundle's band, which a script's blocks can
    /// start. `osacompile`, Script Editor and `store script` write a compiled one, as a `.scpt` or a script bundle's or
    /// applet's `main.scpt`, run-only or not, and osascript writes a script with properties back after running it.
    /// Text AppleScript without a `#!` line is plain text, which its name doesn't change, so it's left out, as is a
    /// JXA text script: `#!/usr/bin/osascript -l JavaScript` names it JavaScript, which node's share.
    static let appleScriptWrittenPredicate = contentWritten([.compiledAppleScript, .appleScriptText])

    /// The predicate a write of a property list matches: a modified close of a `.plist`, or a rename whose
    /// destination is one, as a safe save writes a temporary file and renames it over the property list.
    static let modifiedPropertyListPredicate = written(or: "RENAME") + #" AND target_path ENDSWITH[c] ".plist""#

    /// The predicate an IOKit open of a non-Apple driver's service matches: one whose driver bundle ID is known and
    /// doesn't start with `com.apple.`.
    static let nonAppleDriverPredicate = type("IOKIT_OPEN") + " AND event.iokit_open.driver_bundle_id != nil "
        + #"AND event.iokit_open.driver_bundle_id != "" "#
        + #"AND NOT event.iokit_open.driver_bundle_id BEGINSWITH "com.apple.""#

    /// The predicate an exec of a new executable matches: one created less than
    /// ``ESProcessExecEvent/newExecutableAge`` before it ran. The New executable indicator, its mark, Event Facts'
    /// clock and Event Search's starter search all use it, so they select the same execs.
    static let newExecutableSource = type("EXEC") + " AND event.exec.executable_age_ms >= 0 "
        + "AND event.exec.executable_age_ms < \(Int(ESProcessExecEvent.newExecutableAge * 1000))"
}
