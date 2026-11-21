//
//  BootSession.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Boot session
/// Which start of the Mac an event is from.
///
/// A process is named by its pid and pid version (``ProcessKey``), and both start over when the Mac restarts, so
/// the same key means another process after a restart. Every record carries the boot session's identifier beside
/// its Sensor ID, so a process is one Sensor ID, one boot session and one key, however long the records are kept.
enum BootSession {
    /// This boot session's identifier, a UUID the kernel makes at each start (`kern.bootsessionuuid`), read once:
    /// it can't change while anything runs. `nil` if the kernel won't say.
    static let current: String? = {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 else { return nil }
        var text = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &text, &size, nil, 0) == 0 else { return nil }
        return String(cString: text)
    }()
}
