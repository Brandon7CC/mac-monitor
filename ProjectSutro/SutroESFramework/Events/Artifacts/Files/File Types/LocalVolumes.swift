//
//  LocalVolumes.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Local volumes
/// Which devices are local volumes (`MNT_LOCAL`), remembered per `st_dev`, so a file on a network volume is never read
/// while an event is built: a read there waits on the server.
///
/// Mounts are listed with `getfsstat` and `MNT_NOWAIT`, which answers from the kernel's own copy of each mount's
/// `statfs` without asking a file system (a `statfs` of a path on a network volume waits on its server). A volume's
/// `f_fsid.val[0]` is the `st_dev` of its files. A device no mount has is remembered as not local. The list is read
/// again for a device not seen before.
///
/// Not thread-safe: each ``FileTypeMemory`` keeps its own, used under its capture lane's gate.
final class LocalVolumes {
    /// A mounted volume's `statfs`, named apart from the function.
    private typealias Volume = statfs
    /// Whether each device seen is a local volume.
    private var local: [Int32: Bool] = [:]
    /// Reads the mounted volumes: `(st_dev, is local)` for each.
    private let mounts: () -> [(device: Int32, isLocal: Bool)]

    /// - Parameter mounts: Reads the mounted volumes, ``mountedVolumes()`` by default.
    init(mounts: @escaping () -> [(device: Int32, isLocal: Bool)] = LocalVolumes.mountedVolumes) {
        self.mounts = mounts
    }

    /// Is a device a local volume?
    ///
    /// - Parameter device: A file's `st_dev`.
    /// - Returns: Whether a mount with that device is `MNT_LOCAL`: `false` for a network volume, or a device no mount
    ///   has.
    func isLocal(_ device: Int32) -> Bool {
        if let known = local[device] { return known }
        for mount in mounts() { local[mount.device] = mount.isLocal }
        let known = local[device] ?? false
        local[device] = known
        return known
    }

    /// The mounted volumes, from `getfsstat` with `MNT_NOWAIT`.
    ///
    /// - Returns: Each volume's device (`f_fsid.val[0]`) and whether it's `MNT_LOCAL`, or none if they can't be listed.
    static func mountedVolumes() -> [(device: Int32, isLocal: Bool)] {
        /// Room for a few more than are mounted now, as one can be mounted between the two calls.
        let count = getfsstat(nil, 0, MNT_NOWAIT) + 4
        guard count > 4 else { return [] }
        var volumes = [Volume](repeating: Volume(), count: Int(count))
        let filled = volumes.withUnsafeMutableBufferPointer { buffer in
            getfsstat(buffer.baseAddress, Int32(MemoryLayout<Volume>.stride * buffer.count), MNT_NOWAIT)
        }
        guard filled > 0 else { return [] }
        return volumes.prefix(Int(filled)).map { ($0.f_fsid.val.0, $0.f_flags & UInt32(MNT_LOCAL) != 0) }
    }
}
