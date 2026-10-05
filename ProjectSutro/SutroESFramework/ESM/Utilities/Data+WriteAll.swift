//
//  Data+WriteAll.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Writing every byte
extension Data {
    /// Write every byte to a file descriptor with `write(2)`: retried after `EINTR` and continued after a partial
    /// write, so a reader never sees part of it.
    ///
    /// - Parameter descriptor: An open descriptor, such as a new file or standard output.
    /// - Returns: `nil` once every byte is written, else the failed write's `errno`.
    func writeAll(to descriptor: Int32) -> Int32? {
        withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32? in
            guard let base = bytes.baseAddress else { return nil }
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(descriptor, base + offset, bytes.count - offset)
                if written >= 0 {
                    offset += written
                } else if errno != EINTR {
                    return errno
                }
            }
            return nil
        }
    }
}
