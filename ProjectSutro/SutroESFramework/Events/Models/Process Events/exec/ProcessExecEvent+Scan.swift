//
//  ProcessExecEvent+Scan.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - Scanning the script an exec runs
extension ProcessExecEvent {
    /// The job that scans the script this exec runs, looked up ignoring the script's change time.
    ///
    /// 1. A script the lane read for `script_content`: its bytes, scanned in memory, when it read all of them. Else
    ///    the file, at the path with no symbolic link the lane's open file had, when it's on a local volume.
    /// 2. Endpoint Security's script, when the lane couldn't read it: only a result remembered for it answers.
    /// 3. An AppleScript or JXA applet's script (``AppletScript``).
    ///
    /// The first two get the rule files the exec's interpreter gets (``FileScanKind/ruleFiles(forInterpreter:)``),
    /// and an applet's both, as `osascript`'s. Nothing is worked out until a script is found, so an exec that runs
    /// none allocates nothing here.
    ///
    /// - Parameters:
    ///   - read: What the lane read of the script (``scriptRead``).
    ///   - volumes: The lane's local volumes.
    /// - Returns: The job, or `nil` for an exec that runs no script Mac Monitor found.
    func scanJob(of read: ScriptRead?, volumes: LocalVolumes) -> FileScanner.Job? {
        if let read {
            let files = FileScanKind.ruleFiles(forInterpreter: target.executable?.name)
            if read.isWhole { return FileScanner.Job(bytes: read.bytes, info: read.info, files: files) }
            guard let reader = target.audit_token.map(FileReader.init(token:)),
                  volumes.isLocal(read.info.st_dev) else { return nil }
            return FileScanner.Job(path: read.path, info: read.info, reader: reader, files: files, anyChangeTime: true)
        }
        if let script {
            return FileScanner.Job(unread: FileScanVersion(script.stat),
                                   files: FileScanKind.ruleFiles(forInterpreter: target.executable?.name))
        }
        guard let applet = AppletScript.script(of: target.executable, volumes: volumes),
              let reader = target.audit_token.map(FileReader.init(token:)) else { return nil }
        return FileScanner.Job(path: applet.path, info: applet.info, reader: reader, files: [.xprotect, .scripts],
                               anyChangeTime: true)
    }
}


// MARK: - An applet's script
/// The script an AppleScript or JXA applet runs. Script Editor and `osacompile` save one as a bundle whose executable,
/// Contents/MacOS/applet, is a Mach-O stub that loads Contents/Resources/Scripts/main.scpt into its own process. No
/// exec runs that script, so the applet's exec scans it. The stub loads main.scpt whatever its executable is named, so
/// any bundle's executable is looked at, not only one named `applet`.
public enum AppletScript {
    /// The folder a bundle's executable is in.
    static let executables = "/Contents/MacOS"
    /// Where an applet's script is in its bundle's Contents.
    static let script = "Resources/Scripts/main.scpt"

    /// Where the script would be if a bundle's executable were an applet's stub, from its path alone.
    ///
    /// - Parameter executable: An exec's target executable's path.
    /// - Returns: Its bundle's main.scpt, or `nil` when it isn't in a bundle's Contents/MacOS.
    public static func path(ofBundleExecutable executable: String?) -> String? {
        guard let executable, let slash = executable.utf8.lastIndex(of: UInt8(ascii: "/")) else { return nil }
        /// Byte by byte, since `hasSuffix` on a substring allocates, and every exec on a scanning lane asks.
        let folder = executable.utf8[..<slash]
        guard folder.count >= executables.utf8.count,
              folder.suffix(executables.utf8.count).elementsEqual(executables.utf8) else { return nil }
        return String(executable[..<slash].dropLast("MacOS".count)) + script
    }

    /// The script of the applet an exec runs. An executable outside a bundle's Contents/MacOS costs no system call,
    /// and one in it costs one `lstat`.
    ///
    /// - Parameters:
    ///   - executable: The exec's target executable.
    ///   - volumes: The lane's local volumes: a bundle on a network volume isn't looked in.
    /// - Returns: main.scpt's path and stat, or `nil` when the executable isn't in a bundle, or its bundle has no
    ///   main.scpt that's a regular file.
    static func script(of executable: File?, volumes: LocalVolumes) -> (path: String, info: stat)? {
        guard let executable, volumes.isLocal(Int32(truncatingIfNeeded: executable.stat.st_dev)),
              let path = path(ofBundleExecutable: executable.path) else { return nil }
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
        return (path, info)
    }
}
