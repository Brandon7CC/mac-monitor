//
//  FileReader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Reading a file for a user
/// The user and group a file is read for: those a process runs as, such as an exec's target.
///
/// The Security Extension runs as root, and an exec's arguments can name any file: `python3 -c 1 /etc/sudoers` would
/// have it read a file that user can't. So a file read for a process is only kept when that process could read it too,
/// by its mode bits and ACL, and look up every directory above it. Supplementary groups aren't looked up, nor whom an
/// ACL entry names: where they could decide, the read is refused. A file only they allow is refused, never one they
/// deny.
struct FileReader: Hashable {
    /// The effective user ID.
    let uid: uid_t
    /// The effective group ID.
    let gid: gid_t

    /// - Parameters:
    ///   - uid: The effective user ID.
    ///   - gid: The effective group ID.
    init(uid: uid_t, gid: gid_t) {
        (self.uid, self.gid) = (uid, gid)
    }

    /// The user and group a process runs as.
    ///
    /// - Parameter token: The process's audit token.
    init(token: AuditToken) {
        self.init(uid: uid_t(truncatingIfNeeded: token.euid), gid: gid_t(truncatingIfNeeded: token.egid))
    }

    /// Could this reader read a file with this mode and owner? Root reads anything. Otherwise only one class's bit
    /// counts, as the kernel picks it: the owner's when the reader owns it, else the group's when the reader is in
    /// the file's group, else everyone's. A reader whose own group isn't the file's could still be in it through a
    /// supplementary group, so both the group's bit and everyone's must allow them.
    ///
    /// - Parameter info: The file's `stat`.
    /// - Returns: Whether the reader may read it.
    func canRead(_ info: stat) -> Bool {
        permits(info, owner: S_IRUSR, group: S_IRGRP, other: S_IROTH)
    }

    /// Could this reader read an open file, by its mode bits (``canRead(_:)``), its ACL, and its path
    /// (``canReach(_:)``)?
    ///
    /// - Parameters:
    ///   - info: The open file's `fstat`.
    ///   - descriptor: The open file.
    /// - Returns: `true` for root, else whether its mode allows the reader, no ACL entry denies reading it, and the
    ///   reader can reach it.
    func canRead(_ info: stat, of descriptor: Int32) -> Bool {
        guard uid != 0 else { return true }
        return canRead(info) && !AccessControlList.denies(ACL_READ_DATA, on: descriptor) && canReach(descriptor)
    }

    /// Could this reader look up names in a directory with this mode and owner (its search, or execute, bit)?
    ///
    /// - Parameter info: The directory's `stat`.
    /// - Returns: Whether it's a directory the reader may search.
    func canSearch(_ info: stat) -> Bool {
        info.st_mode & S_IFMT == S_IFDIR && permits(info, owner: S_IXUSR, group: S_IXGRP, other: S_IXOTH)
    }

    /// Could this reader reach an open file by its path: can it search every directory above it? A file another user
    /// can read inside their `0700` home folder is still out of reach.
    ///
    /// `F_GETPATH`'s path has no symbolic links, so each directory is looked at with `lstat`, never followed: one
    /// found to be a link means the path changed since the open, and the read is refused. Following it could judge
    /// some other folder, or wait on a network volume it points to.
    ///
    /// - Parameter descriptor: The open file.
    /// - Returns: Whether every directory from the file's up to `/` is one the reader may search by its mode, and no
    ///   ACL entry denies searching, or `false` when the file's path can't be had or a symbolic link is on it.
    func canReach(_ descriptor: Int32) -> Bool {
        guard uid != 0 else { return true }
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(descriptor, F_GETPATH, &buffer) != -1 else { return false }
        var directory = String(cString: buffer).deletingLastPathComponent
        while true {
            var info = stat()
            guard lstat(directory, &info) == 0, canSearch(info),
                  !AccessControlList.denies(ACL_SEARCH, at: directory) else { return false }
            guard directory != "/", !directory.isEmpty else { return true }
            directory = directory.deletingLastPathComponent
        }
    }

    /// Does a file's mode grant this reader a permission?
    ///
    /// - Parameters:
    ///   - info: The file's `stat`.
    ///   - owner: The permission's bit for the file's owner.
    ///   - group: Its bit for the file's group.
    ///   - other: Its bit for everyone else.
    /// - Returns: `true` for root, or when every bit of the classes the reader could be in is set: the owner's for its
    ///   owner, the group's for a reader whose group is the file's, and both the group's and everyone's for anyone
    ///   else, who may be in the file's group through a supplementary group.
    private func permits(_ info: stat, owner: mode_t, group: mode_t, other: mode_t) -> Bool {
        guard uid != 0 else { return true }
        let bits = info.st_uid == uid ? owner : info.st_gid == gid ? group : group | other
        return info.st_mode & bits == bits
    }
}
