//
//  SIPStatus.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation


// MARK: - System Integrity Protection
/// System Integrity Protection's status, as `csrutil status` names it. Every event records it (`sip_status`): it
/// changes only at a restart, and an event from a Mac with SIP off means something else than one from a Mac with it on.
public enum SIPStatus: String, Equatable, Sendable {
    /// Every protection is on: nothing in the active configuration is allowed.
    case enabled
    /// Every protection `csrutil disable` turns off is off.
    case disabled
    /// Some protections are off, as `csrutil enable --without …` leaves them.
    case custom

    /// What `csrutil disable` allows: untrusted kexts, the file system, `task_for_pid`, the kernel debugger, DTrace and
    /// NVRAM (`0x6f`).
    static let disabledConfiguration: UInt32 = 0x6f

    /// The status an active configuration means.
    ///
    /// - Parameter configuration: The bits `csr_get_active_config` reports.
    public init(configuration: UInt32) {
        if configuration == 0 {
            self = .enabled
        } else if configuration & Self.disabledConfiguration == Self.disabledConfiguration {
            self = .disabled
        } else {
            self = .custom
        }
    }

    /// This Mac's status, or `nil` if the configuration can't be read.
    public static var current: SIPStatus? {
        var configuration: csr_config_t = 0
        guard csr_get_active_config(&configuration) == 0 else { return nil }
        return SIPStatus(configuration: configuration)
    }
}
