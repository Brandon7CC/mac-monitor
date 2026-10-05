//
//  StatFS.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/25.
//

import Foundation

public struct StatFS: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    // fundamental file system block size
    public var f_bsize: UInt32
    // optimal transfer block size
    public var f_iosize: Int32
    
    // total data blocks in file system
    public var f_blocks: UInt64
    // free blocks in fs
    public var f_bfree: UInt64
    // free blocks avail to non-superuser
    public var f_bavail: UInt64
    // total file nodes in file system
    public var f_files: UInt64
    // free file nodes in fs
    public var f_ffree: UInt64
    
    // file system id
    public var f_fsid: [Int32]
    // user that mounted the filesystem
    public var f_owner: uid_t
    
    // type of filesystem
    public var f_type: UInt32
    // copy of mount exported flags
    public var f_flags: UInt32
    // fs sub-type (flavor)
    public var f_fssubtype: UInt32
    // extended flags
    public var f_flags_ext: UInt32
    
    // fs type name
    public var f_fstypename: String
    // directory on which mounted
    public var f_mntonname: String
    // mounted filesystem
    public var f_mntfromname: String
    
    // Ignore id from being decoded
    enum CodingKeys: String, CodingKey {
        case f_bsize, f_iosize, f_blocks, f_bfree, f_bavail, f_files, f_ffree, f_fsid, f_owner, f_type, f_flags, f_fssubtype, f_flags_ext, f_fstypename, f_mntonname, f_mntfromname
    }
    
    public init(from s: Darwin.statfs) {
        self.f_bsize = s.f_bsize
        self.f_iosize = s.f_iosize
        self.f_blocks = s.f_blocks
        self.f_bfree = s.f_bfree
        self.f_bavail = s.f_bavail
        self.f_files = s.f_files
        self.f_ffree = s.f_ffree
        
        self.f_fsid = [s.f_fsid.val.0, s.f_fsid.val.1]
        self.f_owner = s.f_owner
        
        self.f_type = s.f_type
        self.f_flags = s.f_flags
        self.f_fssubtype = s.f_fssubtype
        self.f_flags_ext = s.f_flags_ext
        
        self.f_fstypename = Self.cCharTupleToString(s.f_fstypename)
        self.f_mntonname = Self.cCharTupleToString(s.f_mntonname)
        self.f_mntfromname = Self.cCharTupleToString(s.f_mntfromname)
    }
    
    /// A fixed-size `char` array's text, up to its first NUL.
    ///
    /// Never reads past the array, even when the kernel leaves it without a NUL.
    ///
    /// - Parameter tuple: The array, as Swift imports it (a tuple of `CChar`).
    /// - Returns: The text, decoded as UTF-8.
    private static func cCharTupleToString<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { buffer in
            String(decoding: buffer.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}
