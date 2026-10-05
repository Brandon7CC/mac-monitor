//
//  CommandLineToolLinkScript.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Link script
/// The shell script that changes `/usr/local/bin/macmonitor` as root, behind the administrator password prompt (app
/// context).
///
/// It's a constant in the binary, never a file in the bundle, and it gets only arguments: nothing is ever written into
/// its source, or into the AppleScript that runs it (``appleScriptSource`` quotes each argument with `quoted form of`).
/// It trusts nothing the app saw. As root it checks again that the directory is a directory, that the entry it
/// changes is Mac Monitor's link and still what Settings showed (compare and swap), and that the tool is one Mac
/// Monitor would link, before it changes anything. It never replaces an entry (`ln` without `-f`) or follows a link it
/// finds (`-h`), and runs only `/bin/mkdir`, `/usr/bin/stat`, `/usr/bin/id`, `/usr/sbin/chown`, `/usr/bin/readlink`,
/// `/bin/rm` and `/bin/ln`.
///
/// **A missing directory** is created only inside a real directory the script's own user (root) owns, without `-p`,
/// so nothing anyone else can write stands between the checks and the `chown`, which doesn't follow a link either.
///
/// Usage: `/bin/sh -c "$source" macmonitor-link ACTION TOOL BINDIR EXPECTED` (``CommandLineToolLink/Plan``).
public enum CommandLineToolLinkScript {
    /// The script's `$0`, as `ps` shows it.
    public static let name = "macmonitor-link"
    
    /// The script. Its exit statuses are ``Outcome``'s.
    public static let source = #"""
        set -u
        [ "$#" -eq 4 ] || exit 2
        action="$1" target="$2" bindir="$3" expected="$4"
        link="$bindir/macmonitor"
        ours() { case "$1" in /*.app/Contents/MacOS/macmonitor) return 0 ;; *) return 1 ;; esac; }
        case "$action" in install|remove) ;; *) exit 2 ;; esac
        if [ "$action" = install ]; then
            ours "$target" && [ -f "$target" ] && [ ! -L "$target" ] && [ -x "$target" ] || exit 7
        fi
        if [ ! -e "$bindir" ] && [ ! -L "$bindir" ]; then
            [ "$action" = install ] || exit 0
            parent="${bindir%/*}"
            if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then /bin/mkdir -p -m 0755 "$parent" || exit 3; fi
            [ -d "$parent" ] && [ ! -L "$parent" ] || exit 4
            [ "$(/usr/bin/stat -f %u "$parent")" = "$(/usr/bin/id -u)" ] || exit 4
            /bin/mkdir -m 0755 "$bindir" || exit 3
            [ -d "$bindir" ] && [ ! -L "$bindir" ] || exit 4
            /usr/sbin/chown -h root:wheel "$bindir" || exit 3
        fi
        [ -d "$bindir" ] && [ ! -L "$bindir" ] || exit 4
        if [ -L "$link" ]; then
            current="$(/usr/bin/readlink "$link")" || exit 8
            [ "$current" = "$expected" ] || exit 6
            ours "$current" || exit 5
            if [ "$action" = install ] && [ "$current" = "$target" ]; then exit 0; fi
            /bin/rm -f "$link" || exit 8
        elif [ -e "$link" ]; then
            exit 5
        else
            [ -z "$expected" ] || exit 6
        fi
        [ "$action" = remove ] && exit 0
        /bin/ln -sh "$target" "$link" || exit 8
        """#
    
    /// The AppleScript that runs ``source`` as root. ``AppleScriptHandler`` calls ``handlerName`` with
    /// ``parameters(for:)``: Apple event parameters, never source text.
    public static let appleScriptSource = """
        on run_link(scriptSource, scriptName, actionName, toolPath, binPath, expectedValue, promptText)
            set shellCommand to "/bin/sh -c " & quoted form of scriptSource & " " & quoted form of scriptName
            repeat with eachArgument in {actionName, toolPath, binPath, expectedValue}
                set shellCommand to shellCommand & " " & quoted form of (contents of eachArgument)
            end repeat
            do shell script shellCommand with prompt promptText with administrator privileges
        end run_link
        """
    
    /// The handler ``appleScriptSource`` defines.
    public static let handlerName = "run_link"
    
    /// The handler's parameters for a plan, in order.
    ///
    /// - Parameter plan: The plan.
    /// - Returns: The script, its name, the plan's arguments, and the prompt.
    public static func parameters(for plan: CommandLineToolLink.Plan) -> [String] {
        [source, name] + plan.arguments + [prompt(for: plan)]
    }
    
    /// What the administrator password prompt says Mac Monitor wants to do.
    ///
    /// - Parameter plan: The plan.
    /// - Returns: A sentence.
    public static func prompt(for plan: CommandLineToolLink.Plan) -> String {
        let link = plan.linkPath
        switch plan.action {
        case .install where plan.expected.isEmpty:
            return "Mac Monitor wants to install its command line tool at \(link)."
        case .install:
            return "Mac Monitor wants to point \(link) at this copy of Mac Monitor."
        case .remove:
            return "Mac Monitor wants to remove its command line tool from \(link)."
        }
    }
    
    /// Run a plan as root, behind the administrator password prompt. Call on the main thread: it waits for the
    /// prompt.
    ///
    /// - Parameter plan: The plan.
    /// - Returns: What happened.
    public static func run(_ plan: CommandLineToolLink.Plan) -> Outcome {
        guard let handler = AppleScriptHandler(source: appleScriptSource, handler: handlerName) else {
            return .failed(-1)
        }
        switch handler.call(parameters(for: plan)) {
        case .success: return .done
        case .failure(let failure): return Outcome(status: failure.number)
        }
    }
}


// MARK: - Outcomes
extension CommandLineToolLinkScript {
    /// What a run did: the script's exit status, or the prompt's cancel.
    public enum Outcome: Equatable {
        /// Done (0).
        case done
        /// The user cancelled the prompt (AppleScript's -128).
        case cancelled
        /// Wrong arguments (2): a bug.
        case misused
        /// The link's directory couldn't be created (3).
        case directoryNotCreated
        /// The link's directory isn't a directory, or is a symbolic link; or it's missing, and the directory it would
        /// go in isn't a real one only root owns (4).
        case notADirectory
        /// What's at the link's path isn't Mac Monitor's link (5).
        case notMacMonitors
        /// What's at the link's path changed since Settings looked (6).
        case changed
        /// The tool isn't one Mac Monitor links: not a regular executable file in an app (7).
        case badTool
        /// The file system refused a change (8).
        case fileSystemError
        /// Anything else: the status.
        case failed(Int)
        
        /// - Parameter status: The script's exit status, or AppleScript's error number.
        public init(status: Int) {
            switch status {
            case 0: self = .done
            case -128: self = .cancelled
            case 2: self = .misused
            case 3: self = .directoryNotCreated
            case 4: self = .notADirectory
            case 5: self = .notMacMonitors
            case 6: self = .changed
            case 7: self = .badTool
            case 8: self = .fileSystemError
            default: self = .failed(status)
            }
        }
        
        /// What to tell the user.
        ///
        /// - Parameter plan: The plan that ran.
        /// - Returns: A sentence, or `nil` when there's nothing to say (done, or cancelled).
        public func message(for plan: CommandLineToolLink.Plan) -> String? {
            let link = plan.linkPath
            switch self {
            case .done, .cancelled: return nil
            case .misused: return "Mac Monitor asked for a change to \(link) the script doesn't make. Nothing changed."
            case .directoryNotCreated: return "\(plan.binDirectory) couldn't be created."
            case .notADirectory: return "\(plan.binDirectory) isn't a directory, so Mac Monitor left it alone."
            case .notMacMonitors: return "\(link) isn't Mac Monitor's link, so Mac Monitor left it alone."
            case .changed: return "\(link) changed while you were deciding. Nothing changed: look again, then retry."
            case .badTool: return "\(plan.tool) isn't a command line tool Mac Monitor links. Nothing changed."
            case .fileSystemError: return "The file system refused to change \(link)."
            case .failed(let status): return "Changing \(link) failed (\(status))."
            }
        }
    }
}
