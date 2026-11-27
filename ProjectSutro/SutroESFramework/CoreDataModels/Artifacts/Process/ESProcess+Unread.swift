//
//  ESProcess+Unread.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Values that weren't read
/// What Event Facts reads of a stored process whose values weren't all read. A network flow's process may have no
/// audit token, no group, no executable and no signature (``FlowProcessRecord``). An Endpoint Security process reads
/// as it's stored.
extension ESProcess {
    /// Were its users read? They come from its audit token. Without one, its stored user IDs are zeros, not root's.
    public var hasUsers: Bool { audit_token != nil }

    /// Its process group, or `nil` when it wasn't read (``Process/unread``).
    public var groupID: Int32? { group_id == Process.unread ? nil : group_id }

    /// Its File Quarantine type, or `nil` for `DISABLED` and for a process without an executable, whose type is "".
    public var quarantineType: String? {
        file_quarantine_type.isEmpty || file_quarantine_type == FileQuarantineType.disabled.rawValue
            ? nil : file_quarantine_type
    }

    /// Is how it's signed known? Not without an executable, as a network flow's process may be. Nor when its code
    /// signing type is unknown, as a flow's is when its signature wasn't read. An empty signing ID then doesn't mean
    /// it's unsigned.
    public var isSigningKnown: Bool {
        executable != nil && codesigning_type != CodeSigningType.unknown.rawValue
    }
}
