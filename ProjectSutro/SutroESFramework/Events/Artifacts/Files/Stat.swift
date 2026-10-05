//
//  Stat.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/16/25.
//

import Foundation


// Ensure Stat conforms to Codable and Equatable
public struct Stat: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    // [XSI] File serial number
    public var st_ino: Int64
    // [XSI] ID of device containing file
    public var st_dev: Int64
    // [XSI] file size, in bytes
    public var st_size: Int64
    // [XSI] blocks allocated for file
    public var st_blocks: Int64
    // [XSI] optimal blocksize for I/O
    public var st_blksize: Int64
    // user defined flags for file
    public var st_flags: Int64
    // file generation number
    public var st_gen: Int64
    
    // [XSI] Mode of file (see below)
    public var st_mode: Int64
    // [XSI] Number of hard links
    public var st_nlink: Int64
    // [XSI] User ID of the file
    public var st_uid: Int64
    // [XSI] Group ID of the file
    public var st_gid: Int64
    // [XSI] Device ID
    public var st_rdev: Int64
    
    // time of last access
    public var st_atimespec: TimeSpec
    // time of last data modification
    public var st_mtimespec: TimeSpec
    // time of last status change
    public var st_ctimespec: TimeSpec
    // time of file birth
    public var st_birthtimespec: TimeSpec
    
    public init(from s: Darwin.stat) {
        self.st_ino     = Int64(bitPattern: s.st_ino)

        self.st_size    = s.st_size
        self.st_blocks  = s.st_blocks

        self.st_dev     = Int64(s.st_dev)
        self.st_rdev    = Int64(s.st_rdev)
        self.st_blksize = Int64(s.st_blksize)

        self.st_flags   = Int64(UInt32(s.st_flags))
        self.st_gen     = Int64(s.st_gen)
        self.st_mode    = Int64(UInt16(s.st_mode))
        self.st_nlink   = Int64(UInt16(s.st_nlink))

        self.st_uid     = Int64(s.st_uid)
        self.st_gid     = Int64(s.st_gid)

        self.st_atimespec   = TimeSpec(from: s.st_atimespec)
        self.st_mtimespec   = TimeSpec(from: s.st_mtimespec)
        self.st_ctimespec   = TimeSpec(from: s.st_ctimespec)
        self.st_birthtimespec = TimeSpec(from: s.st_birthtimespec)
    }
}
