//
//  LaunchedByParentColumns.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Launched-by parent columns
/// An exec or fork row that keeps the launched-by parent of the process its event created (``LaunchedByParent``) in
/// plain columns rather than as JSON: storing one sets six values and reading one builds it from them, so neither runs
/// a coder.
///
/// ``ESProcessExecEvent`` and ``ESProcessForkEvent`` hold the columns as Core Data attributes. Every column is `nil`
/// without a launched-by parent.
protocol LaunchedByParentColumns: AnyObject {
    /// ``LaunchedByParent/source``'s JSON value.
    var launched_by_parent_source: String? { get set }
    /// ``LaunchedByParent/resolved_by``'s JSON value.
    var launched_by_parent_resolved_by: String? { get set }
    /// ``LaunchedByParent/pid``.
    var launched_by_parent_pid: NSNumber? { get set }
    /// ``LaunchedByParent/path``.
    var launched_by_parent_path: String? { get set }
    /// The label of ``LaunchedByParent/launchd_job``.
    var launched_by_parent_job: String? { get set }
    /// ``LaunchedByParent/audit_token``'s eight values (``AuditToken/columnData``).
    var launched_by_parent_token: Data? { get set }
}

extension LaunchedByParentColumns {
    /// The launched-by parent the columns hold, or `nil` without one.
    var storedLaunchedByParent: LaunchedByParent? {
        get {
            let source = launched_by_parent_source.flatMap(LaunchedByParent.Source.init(rawValue:))
            let resolvedBy = launched_by_parent_resolved_by.flatMap(LaunchedByParent.ResolvedBy.init(rawValue:))
            guard let source, let resolvedBy else { return nil }
            return LaunchedByParent(source: source,
                                    audit_token: launched_by_parent_token.flatMap(AuditToken.init(columnData:)),
                                    pid: launched_by_parent_pid?.int32Value, path: launched_by_parent_path,
                                    launchd_job: launched_by_parent_job.map(LaunchedByParent.LaunchdJob.init(label:)),
                                    resolved_by: resolvedBy)
        }
        set {
            launched_by_parent_source = newValue?.source.rawValue
            launched_by_parent_resolved_by = newValue?.resolved_by.rawValue
            launched_by_parent_pid = newValue?.pid.map { NSNumber(value: $0) }
            launched_by_parent_path = newValue?.path
            launched_by_parent_job = newValue?.launchd_job?.label
            launched_by_parent_token = newValue?.audit_token?.columnData
        }
    }
}


// MARK: - A token in a column
extension AuditToken {
    /// ``columnData``'s size: eight 64-bit values.
    static let columnSize = 8 * MemoryLayout<Int64>.size
    
    /// The token's eight values as one column holds them: 64-bit integers in this Mac's byte order (the store is new at
    /// every launch), in the order ``init(pid:pidversion:asid:auid:euid:ruid:rgid:egid:)`` takes them.
    var columnData: Data {
        [Int64(pid), Int64(pidversion), Int64(asid), auid, euid, ruid, rgid, egid].withUnsafeBytes { Data($0) }
    }
    
    /// A token from ``columnData``, with the zeroed `id` a ``LaunchedByParent`` stores its token with.
    ///
    /// - Parameter data: The column's value.
    /// - Returns: `nil` when the value isn't ``columnSize`` bytes.
    init?(columnData data: Data) {
        guard data.count == Self.columnSize else { return nil }
        let values = data.withUnsafeBytes { bytes in
            (0..<8).map { bytes.loadUnaligned(fromByteOffset: $0 * MemoryLayout<Int64>.size, as: Int64.self) }
        }
        self.init(pid: Int32(truncatingIfNeeded: values[0]), pidversion: Int32(truncatingIfNeeded: values[1]),
                  asid: Int32(truncatingIfNeeded: values[2]), auid: values[3], euid: values[4], ruid: values[5],
                  rgid: values[6], egid: values[7])
    }
}
