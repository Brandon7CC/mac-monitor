//
//  AccessControlList.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Deny entries
/// The deny entries of a file's extended ACL, which the kernel checks before the file's mode bits.
///
/// Whom an entry names isn't resolved: any entry denying a permission counts, so a reader is refused a file one might
/// deny them, and never let through one that does. An ACL that can't be read counts as one that denies.
enum AccessControlList {
    /// Does an open file's ACL deny a permission to anyone?
    ///
    /// - Parameters:
    ///   - permission: The permission, such as `ACL_READ_DATA`.
    ///   - descriptor: The open file.
    /// - Returns: Whether an entry denies it, or the ACL can't be read. `false` for a file without one.
    static func denies(_ permission: acl_perm_t, on descriptor: Int32) -> Bool {
        denies(permission, in: acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED))
    }

    /// Does the ACL of the file or directory at a path deny a permission to anyone?
    ///
    /// - Parameters:
    ///   - permission: The permission, such as `ACL_SEARCH`.
    ///   - path: The path. A symbolic link at it isn't followed: its own ACL is read.
    /// - Returns: Whether an entry denies it, or the ACL can't be read. `false` for a file without one.
    static func denies(_ permission: acl_perm_t, at path: String) -> Bool {
        denies(permission, in: acl_get_link_np(path, ACL_TYPE_EXTENDED))
    }

    /// Does an ACL just read have an entry denying a permission?
    ///
    /// - Parameters:
    ///   - permission: The permission.
    ///   - acl: The ACL, or `nil` when reading it failed: `ENOENT` means the file has none.
    /// - Returns: Whether an entry denies the permission, or the ACL or one of its entries couldn't be read.
    private static func denies(_ permission: acl_perm_t, in acl: acl_t?) -> Bool {
        guard let acl else { return errno != ENOENT }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        var position = ACL_FIRST_ENTRY.rawValue
        while acl_get_entry(acl, position, &entry) == 0, let current = entry {
            position = ACL_NEXT_ENTRY.rawValue
            var tag = ACL_UNDEFINED_TAG
            var permissions: acl_permset_t?
            guard acl_get_tag_type(current, &tag) == 0, acl_get_permset(current, &permissions) == 0,
                  let permissions else { return true }
            if tag == ACL_EXTENDED_DENY, acl_get_perm_np(permissions, permission) == 1 { return true }
        }
        return false
    }
}
