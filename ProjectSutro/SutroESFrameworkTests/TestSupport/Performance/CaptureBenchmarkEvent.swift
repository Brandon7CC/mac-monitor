//
//  CaptureBenchmarkEvent.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Events the capture benchmarks serialize
/// A raw message the capture benchmarks build and encode, as a capture lane receives it.
///
/// Exec isn't one: `ProcessExecEvent` retains its message with `es_retain_message`, which only takes a message
/// Endpoint Security allocated, so an exec's build can only be timed on a live client. Its encode is timed from an
/// eslogger record (``XCTestCase/benchmarkExec()``).
enum CaptureBenchmarkEvent: String, CaseIterable {
    /// `/private/etc/hosts` opened for reading.
    case open
    /// A 4 KB file closed after it was written.
    case close
    /// A new file named by its directory and name: File Quarantine is read from it.
    case create
    /// `/usr/lib/dyld` mapped read and execute.
    case mmap
    /// A shell (pid 401) forks.
    case fork
    /// `/usr/bin/true` exits.
    case exit
    /// The open, by a validly signed process that isn't a platform binary: its code signing type comes from its
    /// certificates (``CodeSigningCertificateCache``), which are cached after the first event.
    case openByThirdParty = "open.third_party"

    /// The lane its client is.
    var eventClass: EventClass {
        switch self {
        case .fork, .exit: return .process
        case .mmap: return .memory
        default: return .file
        }
    }
}


extension XCTestCase {
    /// The message for a capture benchmark, alive until the test ends.
    ///
    /// - Parameter event: Which event.
    /// - Returns: The message's fixture.
    /// - Throws: The error writing the files a close or create names.
    func rawMessage(for event: CaptureBenchmarkEvent) throws -> RawMessageFixture {
        switch event {
        case .open, .openByThirdParty:
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OPEN)
            fixture.open("/private/etc/hosts")
            if event == .openByThirdParty {
                fixture.message.pointee.process = fixture.process(path: "/usr/bin/true", signingID: "com.example.tool",
                                                                  teamID: "EXAMPLE123", flags: UInt32(CS_VALID),
                                                                  platform: false)
            }
            return fixture
        case .close:
            let file = try temporaryFile(containing: String(repeating: "x", count: 4_096), named: "written.txt")
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CLOSE)
            fixture.close(file.path, modified: true)
            return fixture
        case .create:
            let file = try temporaryFile(containing: "created", named: "Created.txt")
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
            fixture.create(file.lastPathComponent, in: file.deletingLastPathComponent().path)
            return fixture
        case .mmap:
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_MMAP)
            fixture.mmap("/usr/lib/dyld")
            return fixture
        case .fork:
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
            let shell = RawMessageFixture.auditToken(pid: 401, pidversion: 4010)
            fixture.fork(childPID: 4_243, parent: shell, responsible: shell)
            return fixture
        case .exit:
            return rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        }
    }

    /// An exec as a shell starts a command: `/bin/zsh -c 'git status'` with a login session's environment, read from
    /// an eslogger record (see ``CaptureBenchmarkEvent``).
    ///
    /// - Returns: The event.
    /// - Throws: The error reading the record.
    func benchmarkExec() throws -> Message {
        let environment = ["HOME=/Users/user", "USER=user", "LOGNAME=user", "SHELL=/bin/zsh", "TERM=xterm-256color",
                           "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8",
                           "TMPDIR=/var/folders/xx/abcdefghijklmnop/T/", "PWD=/Users/user/Developer",
                           "SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.abcdef/Listeners", "COLORTERM=truecolor",
                           "__CF_USER_TEXT_ENCODING=0x1F5:0x0:0x0", "TERM_PROGRAM=Apple_Terminal", "SHLVL=1",
                           "XPC_FLAGS=0x0", "XPC_SERVICE_NAME=0", "OLDPWD=/Users/user", "_=/usr/bin/git"]
        return try importRecord(try esloggerExec(parent: (401, 4010), args: ["/bin/zsh", "-c", "git status"],
                                                 env: environment))
    }
}
