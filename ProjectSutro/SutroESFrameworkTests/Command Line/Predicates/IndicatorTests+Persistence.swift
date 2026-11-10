//
//  IndicatorTests+Persistence.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Persistence
/// The records each persistence default matches, and the ones close to them it doesn't: one for every place it covers,
/// and the false positives it leaves out. Builds from 1.9 until 3.1.0 wrote a rename's new-path separator as `\/`.
/// The cases that use it cover traces those builds recorded.
extension IndicatorTests {
    /// A case: a default's name, a record it matches, and a record it doesn't.
    typealias Case = (String, NSDictionary, NSDictionary)

    /// - Returns: The persistence defaults' cases, for ``defaultCases()``.
    func persistenceCases() -> [Case] {
        shellStartupCases + scheduledJobCases + authenticationCases + sshCases + browserExtensionCases
            + launchJobCases + dylibCases + pluginCases + terminalStartupCases + loginHookCases + profileCases
            + folderActionCases
    }

    // MARK: Records
    /// - Parameters:
    ///   - type: The event type, without `ES_EVENT_TYPE_NOTIFY_`.
    ///   - path: Its target path.
    ///   - executable: The path of the process that caused it.
    /// - Returns: A file event's record.
    private func file(_ type: String, _ path: String, by executable: String = "/bin/zsh") -> NSDictionary {
        ["es_event_type": "ES_EVENT_TYPE_NOTIFY_\(type)", "target_path": path,
         "process": ["executable": ["path": executable, "name": (executable as NSString).lastPathComponent]]]
    }

    /// - Parameters:
    ///   - path: The file closed.
    ///   - modified: Whether it was written.
    ///   - executable: The path of the process that closed it.
    /// - Returns: A close's record.
    private func close(_ path: String, modified: Bool = true, by executable: String = "/bin/zsh") -> NSDictionary {
        let record = NSMutableDictionary(dictionary: file("CLOSE", path, by: executable))
        record["event"] = ["close": ["modified": modified]]
        return record
    }

    /// - Parameters:
    ///   - path: The executable run.
    ///   - commandLine: Its command line. The context is its first 200 characters.
    ///   - env: Its environment.
    ///   - parent: The path of the executable it replaced.
    ///   - signingID: Its signing ID.
    /// - Returns: An exec's record.
    private func exec(_ path: String, _ commandLine: String, env: [String] = [], by parent: String = "/bin/zsh",
                      signingID: String = "com.example.tool") -> NSDictionary {
        let target: [String: Any] = ["executable": ["path": path, "name": (path as NSString).lastPathComponent],
                                     "signing_id": signingID]
        let exec: [String: Any] = ["command_line": commandLine, "env": env, "target": target]
        return ["es_event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "context": String(commandLine.prefix(200)),
                "process": ["executable": ["path": parent, "name": (parent as NSString).lastPathComponent]],
                "event": ["exec": exec]]
    }

    /// - Parameter commandLine: launchctl's command line.
    /// - Returns: An exec of `/bin/launchctl`.
    private func launchctl(_ commandLine: String) -> NSDictionary {
        exec("/bin/launchctl", commandLine, signingID: "com.apple.xpc.launchctl")
    }

    /// - Parameter context: Its context: `[rights] petitioner → instigator`.
    /// - Returns: An authorization petition's record.
    private func petition(_ context: String) -> NSDictionary {
        ["es_event_type": "ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION", "context": context]
    }

    // MARK: Cases
    private var shellStartupCases: [Case] {
        let name = "Shell startup file modified"
        return [
            (name, close("/Users/a/.zshrc"), close("/private/var/folders/ab/cd/T/brandon-code-zsh/.zshrc")),
            (name, close("/Users/a/.ZSHRC"), close("/Users/a/.zshrc", modified: false)),
            (name, file("CREATE", "/Users/a/.zshrc.zwc"), file("CREATE", "/Users/a/.zsh_history")),
            (name, file("LINK", "/Users/a/.bash_profile"), close("/Users/a/notes.profile.txt")),
            (name, file("RENAME", "/Users/a\\/.zlogin"), file("RENAME", "/Users/a/.zcompdump")),
            (name, close("/Users/a/.config/zsh/.zshenv"), file("MMAP", "/Users/a/.zshenv")),
            (name, close("/Users/a/.bashrc"), close("/Users/a/.config/fish/fish_variables")),
            (name, close("/Users/a/.config/fish/conf.d/x.fish"), close("/Users/a/Documents/zshrc notes.txt")),
            (name, file("CREATE", "/Users/a/.zkbd/xterm-256color-apple-darwin"), close("/Users/a/.zcompdump")),
            (name, close("/private/var/root/.tcshrc"), close("/private/etc/manpaths")),
            (name, close("/private/etc/zshenv"), close("/private/etc/hosts")),
            (name, file("RENAME", "/private/etc/zprofile"), file("RENAME", "/private/etc/ssh/sshd_config")),
            (name, file("RENAME", "/private/etc\\/zshrc_iTerm.app"), close("/Users/a/zshrc")),
            (name, close("/private/etc/bashrc_Apple_Terminal"), close("/private/var/folders/x/T/.bash_profile")),
            (name, close("/private/etc/csh.login"), close("/private/etc/shells")),
            (name, file("CREATE", "/private/etc/paths.d/mmpt"), file("CREATE", "/private/var/folders/x/T/.profile")),
            (name, file("RENAME", "/private/etc\\/paths"), close("/private/etc/paths", modified: false)),
            (name, file("RENAME", "/private/etc/paths"), file("RENAME", "/private/etc/manpaths")),
            (name, close("/private/etc/zshenv.zwc"), close("/private/etc/zshenv.bak")),
            (name, close("/private/etc/profile"), close("/private/etc/profile.d.txt")),
        ]
    }

    private var scheduledJobCases: [Case] {
        let name = "Scheduled job added"
        return [
            (name, file("RENAME", "/private/var/at/tabs\\/a", by: "/usr/bin/crontab"),
             file("RENAME", "/private/var/at/tmp/tmp.15612", by: "/usr/bin/crontab")),
            (name, close("/private/var/at/tabs/root"), close("/private/var/at/tabs/root", modified: false)),
            (name, file("CREATE", "/private/etc/crontab"), file("CREATE", "/private/etc/crontab.bak")),
            (name, file("LINK", "/private/etc/CRONTAB"), file("LINK", "/private/var/at/tmp/x")),
            (name, file("CREATE", "/private/var/at/jobs/a0000401c83e99", by: "/usr/bin/at"),
             file("CREATE", "/private/var/at/jobs/.lockfile", by: "/usr/bin/at")),
            (name, file("RENAME", "/private/var/at/jobs\\/b0000501c83e99"),
             file("CREATE", "/private/var/at/jobs/.SEQ")),
            (name, file("RENAME", "/private/var/at/jobs"), file("CREATE", "/private/var/at/jobs")),
            (name, file("RENAME", "/private/var/at/tabs/a", by: "/usr/bin/crontab"),
             file("RENAME", "/private/var/at/tmp/a", by: "/usr/bin/crontab")),
            (name, file("RENAME", "/private/var/at/jobs/b0000501c83e99"), file("RENAME", "/private/var/at/jobs/.SEQ")),
            (name, launchctl("launchctl enable system/com.apple.atrun"),
             launchctl("launchctl print system/com.apple.atrun")),
            (name, launchctl("/bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.atrun.plist"),
             exec("/usr/bin/grep", "grep enable system/com.apple.atrun")),
        ]
    }

    private var authenticationCases: [Case] {
        let name = "Authentication modified"
        let plugin = "/Library/Security/SecurityAgentPlugins/mmv.bundle"
        let module = "/Library/OpenDirectory/Modules/mmv.xpc"
        let authd = "/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/authd.xpc/Contents/MacOS/"
            + "authd"
        return [
            (name, close("/private/etc/sudoers.d/mmv"), close("/private/etc/sudoers.tmp", by: "/usr/sbin/visudo")),
            (name, file("RENAME", "/private/etc/sudoers", by: "/usr/sbin/visudo"),
             file("CREATE", "/private/etc/sudoers.d/.mmv.swp")),
            (name, file("LINK", "/private/etc/pam.d/sudo_local"), file("CREATE", "/private/etc/pam.d/sudo_local~")),
            (name, file("RENAME", "/private/etc/pam.d\\/mmpt2"), close("/private/etc/pam.d/sudo", modified: false)),
            (name, file("CREATE", "/private/etc/sudo.conf"), close("/private/etc/hosts")),
            (name, close("/usr/local/lib/pam/pam_mmv.so"), close("/usr/local/lib/libmmv.dylib")),
            (name, file("CREATE", plugin), file("CREATE", plugin + "/Contents")),
            (name, file("RENAME", "/Library/OpenDirectory/Modules\\/mmv.xpc"),
             file("CREATE", "/Library/OpenDirectory/Modules/notes.txt")),
            (name, close(plugin + "/Contents/MacOS/mmv"), close(plugin + "/Contents/MacOS/mmv", modified: false)),
            (name, close("/private/var/db/auth.db", by: "/usr/bin/sqlite3"),
             close("/private/var/db/auth.db", by: authd)),
            (name, petition("[config.add.mmv.test.right] security → security"),
             petition("[config.remove.mmv.test.right] security → security")),
            (name, petition("[system.privilege.admin,config.modify.com.example.right] Helper → Helper"),
             petition("[system.preferences.network] security → security")),
            (name, file("RENAME", "/Library/OpenDirectory/Modules/mmv.xpc"),
             file("RENAME", "/Library/OpenDirectory/Modules/mmv.plist")),
            (name, close(module + "/Contents/MacOS/mmv"), close(module + "/Contents/MacOS/mmv", modified: false)),
            (name, close("/private/var/db/auth.db-wal", by: "/usr/bin/sqlite3"),
             close("/private/var/db/auth.db-wal", by: authd)),
            (name, file("RENAME", "/Library/Security/SecurityAgentPlugins"),
             file("RENAME", "/private/tmp/stage/Library/Security/SecurityAgentPlugins")),
            (name, file("RENAME", "/Library/OpenDirectory\\/modules"),
             file("RENAME", "/Library/Security/SecurityAgentPlugins.old")),
        ]
    }

    private var sshCases: [Case] {
        let name = "SSH access modified"
        return [
            (name, close("/Users/a/.ssh/authorized_keys"), close("/Users/a/.ssh/authorized_keys", modified: false)),
            (name, file("CREATE", "/Users/a/.ssh/AUTHORIZED_KEYS"), file("CREATE", "/Users/a/.ssh/id_ed25519")),
            (name, file("LINK", "/private/var/root/.ssh/authorized_keys"),
             file("CREATE", "/Volumes/Backup/Users/a/.ssh/authorized_keys")),
            (name, close("/Users/a/.ssh/authorized_keys2"), close("/Users/a/.ssh/known_hosts")),
            (name, file("RENAME", "/Users/a/.ssh\\/rc"), close("/Users/a/.ssh/config")),
            (name, file("RENAME", "/Users/a\\/.ssh"), file("CREATE", "/Users/a/.ssh")),
            (name, close("/private/etc/ssh/sshd_config.d/099-mmpt.conf"), close("/private/etc/ssh/ssh_config")),
            (name, close("/private/etc/ssh/sshrc"), close("/private/etc/ssh/ssh_host_ed25519_key")),
            (name, file("CREATE", "/private/etc/ssh/crypto.conf"), close("/private/etc/ssh/ssh_config.d/100.conf")),
            (name, file("RENAME", "/Users/a/.ssh/rc"), file("RENAME", "/Users/a/.ssh/known_hosts")),
            (name, file("RENAME", "/Users/a/.ssh"), file("RENAME", "/Volumes/Backup/Users/a/.ssh")),
        ]
    }

    private var browserExtensionCases: [Case] {
        let name = "Browser extension sideloaded"
        let chrome = "/Users/a/Library/Application Support/Google/Chrome"
        let chromium = "/Applications/Chromium.app/Contents/MacOS/Chromium"
        let flags = " --user-data-dir=/Users/a/Library/Application Support/Chromium/"
            + String(repeating: "p", count: 200)
        return [
            (name, close(chrome + "/External Extensions/aaaa.json"),
             close(chrome + "/External Extensions/aaaa.json", modified: false)),
            (name, file("RENAME", chrome + "/external extensions\\/bbbb.JSON"),
             file("RENAME", chrome + "/Default/Extensions/bbbb/1.0/manifest.json")),
            (name, file("RENAME", "/Library/Application Support/BraveSoftware/Brave-Browser\\/External Extensions"),
             file("CREATE", "/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions")),
            (name, file("LINK", "/Library/Application Support/Google/Chrome/External Extensions/cccc.json"),
             file("CREATE", chrome + "/External Extensions/cccc.json")),
            (name, exec(chromium, chromium + " --load-extension=/tmp/ext", by: "/bin/bash"),
             exec("/usr/bin/grep", "grep -c -- --load-extension=")),
            (name, exec(chromium, chromium + " -load-extension=/tmp/ext", by: "/usr/libexec/xpcproxy"),
             exec(chromium, chromium + " --load-extension=/tmp/ext", by: "/opt/homebrew/bin/node")),
            (name, exec(chromium, chromium + flags + " --load-extension=/tmp/ext"),
             exec(chromium, chromium + " --disable-extensions")),
            (name, file("RENAME", chrome + "/External Extensions/dddd.json"),
             file("RENAME", chrome + "/External Extensions/dddd.json.tmp")),
            (name, file("RENAME", "/Library/Application Support/Google/Chrome/External Extensions"),
             file("RENAME", chrome + "/External Extensions.bak")),
        ]
    }

    private var launchJobCases: [Case] {
        let name = "Launch job loaded"
        return [
            (name, launchctl("/bin/launchctl bootstrap gui/501 /tmp/mmv/mmv.persist.plist"),
             launchctl("/bin/launchctl print gui/501")),
            (name, launchctl("launchctl load -w /private/tmp/x.plist"),
             launchctl("/bin/launchctl load -w //Library/LaunchDaemons/com.example.daemon.plist")),
            (name, launchctl("launchctl submit -l mmpt.submit -- /bin/echo hi"),
             launchctl("/bin/launchctl bootstrap gui/501 /Users/a/Library/LaunchAgents/homebrew.mxcl.x.plist")),
            (name, launchctl("launchctl bootstrap gui/501 /tmp/evil.plist /Library/LaunchAgents/x.plist"),
             launchctl("launchctl load /library/launchdaemons/com.example.daemon.plist")),
            (name, launchctl("launchctl load /Users/a/Library/LaunchAgents/../../../../tmp/e.plist"),
             launchctl("launchctl Load /tmp/x.plist")),
            (name, launchctl("launchctl load /Users/a/Library/LaunchAgents/sub/e.plist"),
             launchctl("launchctl bootstrap system /Library/LaunchDaemons/com.example.daemon.plist")),
            (name, launchctl("launchctl load /Users/a/Downloads/Library/LaunchAgents/e.plist"),
             launchctl("launchctl unload /tmp/x.plist")),
            (name, launchctl("launchctl bootstrap gui/501 /opt/homebrew/opt/x/homebrew.mxcl.x.plist"),
             exec("/usr/bin/grep", "grep -r launchctl load /tmp/x.plist")),
            (name, exec("/tmp/lc", "lc bootstrap gui/501 /tmp/x.plist", signingID: "com.apple.xpc.launchctl"),
             exec("/tmp/lc", "lc bootstrap gui/501 /tmp/x.plist", signingID: "a.out")),
            (name, launchctl(String(repeating: "l", count: 210) + " bootstrap gui/501 /tmp/x.plist"),
             launchctl(String(repeating: "l", count: 210) + " list")),
            (name, launchctl("launchctl submit -l x -- /Library/LaunchAgents/x"),
             launchctl("launchctl load -w /Library/LaunchAgents/x.plist")),
            (name, launchctl("launchctl submit -l x -- /Users/a/Library/LaunchAgents/x"),
             launchctl("launchctl load /Users/a/Library/LaunchAgents/x.plist")),
            (name, launchctl("launchctl bootstrap gui/501 /Library/LaunchAgents/x.plist evil.plist"),
             launchctl("/bin/launchctl bootstrap gui/501 /Library/LaunchAgents/x.plist")),
            (name, launchctl("launchctl load /Library/LaunchAgents/x.plist stagedir"),
             launchctl("launchctl load -F //Library/LaunchAgents/x.plist")),
            (name, launchctl("launchctl load stagedir /Library/LaunchAgents/x.plist"),
             launchctl("launchctl bootstrap user/501 /Users/a/Library/LaunchAgents/x.plist")),
            (name, launchctl("launchctl bootstrap gui/501 stagedir /Library/LaunchAgents/x.plist"),
             launchctl("launchctl load -wF /Library/LaunchDaemons/x.plist")),
        ]
    }

    private var dylibCases: [Case] {
        let name = "Dylib inserted"
        let xpcproxy = "/usr/libexec/xpcproxy"
        let insert = "DYLD_INSERT_LIBRARIES=/tmp/x.dylib"
        let xcodeLibrary = "DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/usr/lib/"
            + "libMainThreadChecker.dylib"
        let built = "/Users/a/Library/Developer/Xcode/DerivedData/X/Build/Products/Debug/X.app/Contents/MacOS/X"
        let terminal = "XPC_SERVICE_NAME=application.com.apple.Terminal.1"
        let beta = "/Applications/Xcode-beta.app/Contents/Developer/usr/lib/"
        let xcodePair = "DYLD_INSERT_LIBRARIES=\(beta)libBacktraceRecording.dylib:\(beta)libMainThreadChecker.dylib"
        let sanitizer = "DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/Toolchains/"
            + "XcodeDefault.xctoolchain/usr/lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib"
        let gmalloc = "DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib"
        let lookalike = "/Applications/Xcode/X.app/Contents/Developer/x.dylib"
        func inserted(_ value: String) -> NSDictionary { exec(built, built, env: [value], by: xpcproxy) }
        return [
            (name, exec("/bin/echo", "/bin/echo hi", env: [insert, "XPC_SERVICE_NAME=mmv.agent"], by: xpcproxy),
             exec("/usr/bin/true", "/usr/bin/true", env: [terminal])),
            /// A one-off injection from a shell counts too, as the built-in mark this replaces did.
            (name, exec("/usr/bin/true", "/usr/bin/true", env: [insert, terminal]),
             exec("/usr/bin/true", "/usr/bin/true", env: ["DYLD_LIBRARY_PATH=/tmp", terminal])),
            (name, exec("/tmp/prog", "/tmp/prog", env: ["XPC_SERVICE_NAME=com.example.agent", insert], by: "/bin/sh"),
             exec("/tmp/prog", "/tmp/prog", env: ["XPC_SERVICE_NAME=0", "DYLD_PRINT_LIBRARIES=1"], by: "/bin/sh")),
            (name, exec("/Applications/X.app/Contents/MacOS/X", "X", env: [xcodeLibrary], by: xpcproxy),
             exec(built, built, env: [xcodeLibrary, "XPC_SERVICE_NAME=application.X.1"], by: xpcproxy)),
            (name, exec(built, built, env: [insert], by: xpcproxy),
             exec(built, built, env: ["DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib"], by: xpcproxy)),
            (name, exec("/tmp/prog", "/tmp/prog", env: [insert], by: xpcproxy),
             exec("/usr/libexec/corespotlightd", "corespotlightd",
                  env: ["no_DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib"], by: xpcproxy)),
            (name, launchctl("launchctl setenv DYLD_INSERT_LIBRARIES /tmp/x.dylib"),
             launchctl("launchctl setenv PATH /usr/bin")),
            (name, exec("/tmp/prog", "/tmp/prog", env: [insert], by: "/usr/bin/login"),
             exec("/tmp/prog", "/tmp/prog", env: ["dyld_insert_libraries=/tmp/x.dylib"], by: "/usr/bin/login")),
            (name, inserted(xcodeLibrary + ":/tmp/evil.dylib"), inserted(xcodePair)),
            (name, inserted(gmalloc + ":/tmp/e.dylib"), inserted(sanitizer)),
            (name, inserted("DYLD_INSERT_LIBRARIES=/Applications/XcodeHelper/evil.dylib"), inserted(gmalloc)),
            (name, inserted("DYLD_INSERT_LIBRARIES=" + lookalike), inserted(xcodeLibrary)),
            (name, inserted("DYLD_INSERT_LIBRARIES=\(beta)libBacktraceRecording.dylib:" + lookalike),
             exec("/Applications/Xcode.app/Contents/MacOS/Xcode", "Xcode", env: [xcodeLibrary], by: xpcproxy)),
            (name, inserted(xcodePair + ":/tmp/evil.dylib"), inserted(xcodePair)),
            (name, inserted("DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/../../../../tmp/e.dylib"),
             inserted(xcodeLibrary)),
        ]
    }

    private var pluginCases: [Case] {
        let name = "Plug-in installed"
        return [
            (name, file("CREATE", "/Users/a/Library/screen savers/x.saver"),
             file("CREATE", "/Volumes/Backup/Users/a/Library/Screen Savers/x.saver")),
            (name, file("RENAME", "/Users/a/Library/Screen Savers"),
             file("CREATE", "/Users/a/Library/Screen Savers/x.saver/Contents/MacOS/x")),
            (name, file("CREATE", "/Users/a/Library/Screen Savers", by: "/bin/ln"),
             file("CREATE", "/Users/a/Library/Application Support/X/Screen Savers")),
            (name, file("CREATE", "/Library/Screen Savers/x.saver"), close("/Library/Screen Savers/x.saver")),
            (name, file("RENAME", "/Users/a/Library\\/ColorPickers"),
             file("CREATE", "/Users/a/Library/Containers/c/Data/Library/ColorPickers")),
            (name, file("CREATE", "/Library/ColorPickers/x.colorPicker"),
             file("CREATE", "/private/tmp/X.dst/Library/PreferencePanes/X.prefPane")),
            (name, file("RENAME", "/Users/a/Library/Spotlight\\/mmv.mdimporter"),
             file("CREATE", "/Applications/X.app/Contents/Library/Spotlight/X.mdimporter")),
            (name, file("CREATE", "/Library/Spotlight/x.mdimporter"),
             file("CREATE", "/System/Library/Spotlight/X.mdimporter")),
            (name, file("RENAME", "/Library/PreferencePanes/x.prefPane"),
             file("CREATE", "/Users/a/Applications/X.app/Contents/Library/Spotlight/x.mdimporter")),
            (name, file("CREATE", "/Users/a/Library/Input Methods/x.app"),
             file("CREATE", "/Users/a/Library/Audio/Plug-Ins/HAL/x.driver")),
            (name, file("CREATE", "/Library/Input Methods/x.app"),
             file("CREATE", "/Library/Input Methods/x.app/Contents/Info.plist")),
            (name, file("CREATE", "/Users/a/Library/PreferencePanes/x.prefPane"),
             file("CREATE", "/Users/a/build/root/Library/PreferencePanes/X.prefPane")),
            (name, file("CREATE", "/Users/a/Library/ColorPickers/x.colorPicker"),
             file("CREATE", "/Users/a/Library/Developer/Xcode/Archives/2026-11-06/X.xcarchive/Products/Users/a/Library/"
                  + "Screen Savers/X.saver")),
            (name, file("RENAME", "/Users/a/Library/ColorPickers"),
             file("RENAME", "/Users/a/build/root/Library/Screen Savers")),
            (name, file("RENAME", "/Users/a/Library/Spotlight/x.mdimporter"),
             file("RENAME", "/Users/a/Backups/Users/b/Library/Spotlight/x.mdimporter")),
            (name, file("RENAME", "/Library/Audio/Plug-Ins/HAL/x.driver"),
             file("RENAME", "/Library/Audio/Plug-Ins/HAL/x.driver/Contents/MacOS/x")),
            (name, file("RENAME", "/Library/Audio/Plug-Ins/HAL\\/x.driver"),
             file("CREATE", "/Library/InstallerSandboxes/.PKInstallSandboxManager/u.activeSandbox/Root/Library/Audio/"
                  + "Plug-Ins/HAL/x.driver")),
        ]
    }

    private var terminalStartupCases: [Case] {
        let name = "Terminal startup command"
        let iterm = "/Users/a/Library/Application Support/iTerm2"
        let autoLaunch = iterm + "/Scripts/AutoLaunch"
        let defaults = "/usr/bin/defaults"
        let buddy = "/usr/libexec/PlistBuddy"
        let terminal = "/Users/a/Library/Preferences/com.apple.Terminal.plist"
        let itermPreferences = "/Users/a/Library/Preferences/com.googlecode.iterm2.plist"
        let finder = "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        return [
            (name, close(autoLaunch + "/x.scpt", by: "/usr/bin/python3"),
             close(autoLaunch + "/x.scpt", modified: false)),
            (name, file("CREATE", autoLaunch + "/x.py"), file("CREATE", autoLaunch)),
            (name, file("RENAME", autoLaunch + "\\/x.scpt"),
             file("RENAME", "/Volumes/Backup/Users/a/Library/Application Support/iTerm2/Scripts/AutoLaunch/x.scpt")),
            /// A script in iTerm2's Scripts menu runs only when it's picked.
            (name, close(iterm + "/AutoLaunch.scpt"), close(iterm + "/Scripts/x.py")),
            (name, file("LINK", "/Users/a/Library/application support/iterm2/scripts/autolaunch/x.py"),
             file("CREATE", "/Users/a/Library/Containers/c/Data/Library/Application Support/iTerm2/Scripts/AutoLaunch/"
                  + "x.py")),
            (name, file("CREATE", autoLaunch + "/x/x.py"), file("RENAME", terminal, by: "/usr/sbin/cfprefsd")),
            (name, exec(defaults, "/usr/bin/defaults import com.apple.Terminal /tmp/t.plist"),
             exec(defaults, #"defaults write com.apple.Terminal "Default Window Settings" -string Pro"#)),
            (name, exec(buddy, #"PlistBuddy -c "Set :'Window Settings':Basic:CommandString /tmp/x" \#(terminal)"#),
             exec(buddy, #"PlistBuddy -c "Print :'Window Settings':Basic:CommandString" \#(terminal)"#)),
            (name, exec(defaults, #"defaults write com.googlecode.iterm2 "New Bookmarks" -array '{"Custom Command" "#
                            + #"= Yes; Command = "/tmp/x"; }'"#),
             exec(defaults, "defaults write com.googlecode.iterm2 PromptOnQuit -bool false")),
            (name, exec("/usr/bin/plutil", #"plutil -replace "New Bookmarks.0.Initial Text" -string /tmp/x "#
                            + "/Users/a/Library/Preferences/com.googlecode.iterm2.plist"),
             exec("/bin/sh", #"/bin/sh -c defaults read com.apple.Terminal "Window Settings" | grep CommandString"#)),
            (name, exec(defaults, "defaults import com.googlecode.iterm2 /tmp/i.plist"),
             exec(defaults, "defaults export com.googlecode.iterm2 /tmp/i.plist")),
            /// A full-environment script's own Python runtime, copied in beside it.
            (name, file("CREATE", autoLaunch + "/x/setup.cfg"),
             file("CREATE", autoLaunch + "/x/iterm2env/versions/3.12/lib/python3.12/os.py")),
            /// Python's cache, written the first time the script runs.
            (name, close(autoLaunch + "/x/x/x.py"),
             close(autoLaunch + "/x/x/__pycache__/x.cpython-312.pyc", by: "/usr/bin/python3")),
            /// Finder's view settings, when someone reveals the folder from iTerm2's Scripts menu.
            (name, file("RENAME", autoLaunch + "/x.py"), file("CREATE", autoLaunch + "/.DS_Store", by: finder)),
            /// The folder iTerm builds before iTerm2 ran AutoLaunch.scpt from.
            (name, file("CREATE", "/Users/a/Library/Application Support/iTerm/AutoLaunch.scpt"),
             file("CREATE", "/Users/a/Library/Application Support/iTerm/x.scpt")),
            /// A profile already set to run a custom command runs whatever its Command key says.
            (name, exec(buddy, #"PlistBuddy -c "Set :New\ Bookmarks:0:Command /tmp/x" \#(itermPreferences)"#),
             exec("/usr/bin/python3", "python3 -c import plistlib; print(plistlib.load(open('\(itermPreferences)',"
                    + "'rb')))")),
            (name, exec("/usr/bin/plutil", #"plutil -replace "New Bookmarks.0.Command" -string /tmp/x "#
                            + itermPreferences),
             exec(buddy, #"PlistBuddy -c "Delete :'Window Settings':Basic:CommandString" \#(terminal)"#)),
        ]
    }

    private var loginHookCases: [Case] {
        let name = "Login hook set"
        let defaults = "/usr/bin/defaults"
        let buddy = "/usr/libexec/PlistBuddy"
        let root = "/private/var/root/Library/Preferences/com.apple.loginwindow.plist"
        return [
            (name, exec(defaults, "defaults write com.apple.loginwindow LoginHook -string /Users/Shared/h.sh",
                        by: "/usr/bin/sudo"),
             exec(defaults, "defaults write com.apple.loginwindow SHOWFULLNAME -bool true", by: "/usr/bin/sudo")),
            (name, exec(buddy, #"PlistBuddy -c "Add :LogoutHook string /Users/Shared/h.sh" \#(root)"#),
             exec(defaults, "defaults read com.apple.loginwindow LoginHook")),
            (name, exec(defaults, "defaults write com.apple.LoginWindow loginhook /Users/Shared/h.sh"),
             exec(defaults, "defaults delete com.apple.loginwindow LoginHook")),
            (name, exec("/usr/bin/plutil", "plutil -replace LogoutHook -string /Users/Shared/h.sh " + root),
             exec(buddy, #"PlistBuddy -c "Delete :LogoutHook" \#(root)"#)),
            (name, close(root, by: buddy), file("RENAME", root, by: "/usr/sbin/cfprefsd")),
            (name, file("RENAME", "/private/var/root/Library/Preferences\\/com.apple.loginwindow.plist",
                        by: "/usr/bin/python3"),
             close(root, modified: false, by: buddy)),
            /// loginwindow keeps its own preferences in each home folder.
            (name, file("CREATE", root, by: "/bin/cp"),
             close("/Users/a/Library/Preferences/com.apple.loginwindow.plist",
                   by: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow")),
            /// An import sets whatever hooks the file holds, as a harness restoring its backup does.
            (name, exec(defaults, "defaults import com.apple.loginwindow /tmp/l.plist", by: "/usr/bin/sudo"),
             exec(defaults, "defaults export com.apple.loginwindow /tmp/l.plist", by: "/usr/bin/sudo")),
            (name, exec(defaults, "/usr/bin/defaults -currentHost import com.apple.loginwindow /tmp/l.plist"),
             exec("/usr/bin/plutil", "plutil -remove LoginHook " + root)),
            (name, exec("/bin/sh", "/bin/sh -c defaults write com.apple.loginwindow LoginHook /Users/Shared/h.sh"),
             exec("/usr/bin/plutil", "plutil -extract LoginHook raw " + root)),
        ]
    }

    private var profileCases: [Case] {
        let name = "Configuration profile installed"
        let mdmclient = "/usr/libexec/mdmclient"
        let purgatory = "/private/var/db/ConfigurationProfiles/Store/ProfilePurgatory"
        let staged = purgatory + "/5F92_DCB8.mobileconfig.profilepurgatory"
        return [
            (name, ["es_event_type": "ES_EVENT_TYPE_NOTIFY_PROFILE_ADD"],
             close("/private/var/db/ConfigurationProfiles/Store/MDM_ComputerPrefs.plist", by: mdmclient)),
            (name, file("CREATE", staged, by: mdmclient), file("CREATE", purgatory, by: mdmclient)),
            (name, file("RENAME", purgatory + "\\/x.mobileconfig.profilepurgatory"),
             file("CREATE", "/private/var/db/ConfigurationProfiles/Settings/.profilePurgatoryExists", by: mdmclient)),
            (name, file("CREATE", staged.lowercased()), close(staged, by: mdmclient)),
            (name, file("RENAME", purgatory),
             file("CREATE", "/Users/a/Downloads/x.mobileconfig", by: "/Applications/Safari.app/Contents/MacOS/Safari")),
        ]
    }

    private var folderActionCases: [Case] {
        let name = "Folder Action attached"
        let scripts = "/Users/a/Library/Scripts/Folder Action Scripts"
        let dispatcher = "/Users/a/Library/Preferences/com.apple.FolderActionsDispatcher.plist"
        let cfprefsd = "/usr/sbin/cfprefsd"
        let finder = "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        return [
            (name, file("CREATE", scripts + "/x.scpt", by: "/usr/bin/python3"), file("CREATE", scripts)),
            (name, close(scripts + "/x.scpt"), close(scripts + "/x.scpt", modified: false)),
            (name, file("RENAME", dispatcher, by: cfprefsd),
             file("RENAME", "/Users/a/Library/Preferences/com.apple.finder.plist", by: cfprefsd)),
            (name, close(dispatcher),
             close("/Volumes/Backup/Users/a/Library/Preferences/com.apple.FolderActionsDispatcher.plist")),
            /// A script in the Scripts menu runs only when it's picked.
            (name, file("RENAME", "/Users/a/Library/Preferences\\/com.apple.FolderActionsDispatcher.plist"),
             file("CREATE", "/Users/a/Library/Scripts/x.scpt")),
            (name, file("LINK", "/Users/a/library/scripts/folder action scripts/x.scpt"),
             file("CREATE", "/Users/a/Library/Containers/com.apple.ScriptEditor2/Data/Library/Scripts/"
                  + "Folder Action Scripts/x.scpt")),
            (name, file("RENAME", scripts), close(dispatcher, modified: false, by: cfprefsd)),
            /// Finder's view settings, when someone opens the folder.
            (name, file("CREATE", scripts + "/x.applescript"),
             file("CREATE", scripts + "/.DS_Store", by: finder)),
        ]
    }
}
