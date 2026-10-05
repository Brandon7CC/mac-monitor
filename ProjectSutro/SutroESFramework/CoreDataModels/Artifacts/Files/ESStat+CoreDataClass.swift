//
//  Stat+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/9/25.
//
//

import Foundation
import CoreData

@objc(ESStat)
public class ESStat: NSManagedObject {
    convenience init(
        from stat: Stat,
        insertIntoManagedObjectContext context: NSManagedObjectContext
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESStat", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = stat.id
        self.st_dev = stat.st_dev
        self.st_blksize = stat.st_blksize
        self.st_blocks = stat.st_blocks
        self.st_flags = stat.st_flags
        self.st_gen = stat.st_gen
        self.st_gid = stat.st_gid
        self.st_ino = stat.st_ino
        self.st_mode = stat.st_mode
        self.st_nlink = stat.st_nlink
        self.st_rdev = stat.st_rdev
        self.st_size = stat.st_size
        self.st_uid = stat.st_uid
        self.st_atimespec = stat.st_atimespec.humanFormat()
        self.st_birthtimespec = stat.st_birthtimespec.humanFormat()
        self.st_ctimespec = stat.st_ctimespec.humanFormat()
        self.st_mtimespec = stat.st_mtimespec.humanFormat()
    }
}

// MARK: - Encodable conformance
extension ESStat: Encodable {
    enum CodingKeys: CodingKey {
        case id, st_dev, st_blksize, st_blocks, st_flags, st_gen, st_gid, st_ino, st_mode, st_nlink, st_rdev, st_size, st_uid, st_atimespec, st_birthtimespec, st_ctimespec, st_mtimespec
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
//        try container.encode(id, forKey: .id)
        try container.encode(st_dev, forKey: .st_dev)
        try container.encode(st_blksize, forKey: .st_blksize)
        try container.encode(st_blocks, forKey: .st_blocks)
        try container.encode(st_flags, forKey: .st_flags)
        try container.encode(st_gen, forKey: .st_gen)
        try container.encode(st_gid, forKey: .st_gid)
        /// `ino_t` is unsigned, and kept by bit pattern: a file ID on SMB, NFS or FUSE can be 2^63 or more, which
        /// eslogger writes unsigned.
        try container.encode(UInt64(bitPattern: st_ino), forKey: .st_ino)
        try container.encode(st_mode, forKey: .st_mode)
        try container.encode(st_nlink, forKey: .st_nlink)
        try container.encode(st_rdev, forKey: .st_rdev)
        try container.encode(st_size, forKey: .st_size)
        try container.encode(st_uid, forKey: .st_uid)
        try container.encode(st_atimespec, forKey: .st_atimespec)
        try container.encode(st_birthtimespec, forKey: .st_birthtimespec)
        try container.encode(st_ctimespec, forKey: .st_ctimespec)
        try container.encode(st_mtimespec, forKey: .st_mtimespec)
    }
}
