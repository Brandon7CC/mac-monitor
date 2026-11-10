//
//  SystemProcExitMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// What an `exit` event says: how the process ended, and the process.
struct SystemProcExitMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.exit {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactsBox {
                        ExitStatusFacts(status: event.stat)
                    }
                    ProcessView(message: esSystemEvent, process: esSystemEvent.process,
                                ageText: esSystemEvent.processAgeText)
                }
            }
        }
    }
}


// MARK: - Exit status
/// How a process ended, read from its `wait(2)` status: the code it exited with, or the signal that ended or stopped
/// it. The status itself is in the tooltip.
struct ExitStatusFacts: View {
    /// Signal names by number, from `<sys/signal.h>`: 1 (`SIGHUP`) to 31 (`SIGUSR2`).
    private static let signalNames = [
        "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGEMT", "SIGFPE", "SIGKILL", "SIGBUS",
        "SIGSEGV", "SIGSYS", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGURG", "SIGSTOP", "SIGTSTP", "SIGCONT", "SIGCHLD",
        "SIGTTIN", "SIGTTOU", "SIGIO", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGINFO", "SIGUSR1",
        "SIGUSR2",
    ]

    /// The `wait(2)` status.
    let status: Int32

    /// The low seven bits: 0 for an exit, `0x7f` for a stop, else the signal that ended the process (`WTERMSIG`).
    private var low: Int32 { status & 0x7f }
    /// The second byte: the exit code (`WEXITSTATUS`), or the signal that stopped the process (`WSTOPSIG`).
    private var high: Int32 { (status >> 8) & 0xff }

    var body: some View {
        Group {
            switch low {
            case 0:
                FactRow(name: "Exit code", value: String(high))
            case 0x7f:
                FactRow(name: "Stopped by signal", value: Self.signal(high))
            default:
                FactRow(name: "Terminated by signal",
                        value: Self.signal(low) + ((status & 0x80) != 0 ? ", core dumped" : ""))
            }
        }.help("wait(2) status: \(status)")
    }

    /// - Parameter number: A signal's number.
    /// - Returns: Its name and number, `SIGKILL (9)`, or its number alone when it has no name.
    private static func signal(_ number: Int32) -> String {
        let index = Int(number) - 1
        return signalNames.indices.contains(index) ? "\(signalNames[index]) (\(number))" : String(number)
    }
}
