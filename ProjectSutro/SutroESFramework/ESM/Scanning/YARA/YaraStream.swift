//
//  YaraStream.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - A stream over a file
/// A `YR_STREAM` over a file descriptor, which libyara saves compiled rules to and loads them from.
///
/// `YR_STREAM` is three pointers in both YARA 3 and 4: the user data, a read function and a write function, each
/// called as `fread` and `fwrite` are. libyara moves compiled rules a few bytes at a time, so the stream keeps a buffer
/// of ``capacity`` bytes and makes one system call per buffer: on macOS 13, loading Apple's 34 MB of compiled rules
/// a system call at a time took 2.3 seconds of CPU.
///
/// A stream is for reading or for writing, not both. After writing, call ``flush()``.
final class YaraStream {
    typealias Read = @convention(c) (UnsafeMutableRawPointer?, Int, Int, UnsafeMutableRawPointer?) -> Int
    typealias Write = @convention(c) (UnsafeRawPointer?, Int, Int, UnsafeMutableRawPointer?) -> Int

    /// How many bytes the stream buffers.
    static let capacity = 1 << 20

    /// The `YR_STREAM`, whose user data is this stream.
    let pointer: UnsafeMutableRawPointer
    /// The open file. The stream doesn't close it.
    private let descriptor: Int32
    private let buffer: UnsafeMutableRawPointer
    /// The bytes read and not yet handed over: `buffer[start..<end]`.
    private var start = 0, end = 0
    /// The bytes written and not yet flushed: `buffer[0..<pending]`.
    private var pending = 0
    /// Did a system call fail? Once it has, every later call fails too.
    private(set) var failed = false

    /// - Parameter descriptor: The open file, read or written from its current offset. The stream doesn't close it.
    init(descriptor: Int32) {
        self.descriptor = descriptor
        buffer = UnsafeMutableRawPointer.allocate(byteCount: Self.capacity, alignment: 16)
        let word = MemoryLayout<UnsafeRawPointer>.stride
        pointer = UnsafeMutableRawPointer.allocate(byteCount: word * 3, alignment: word)
        pointer.storeBytes(of: Unmanaged.passUnretained(self).toOpaque(), as: UnsafeMutableRawPointer.self)
        pointer.storeBytes(of: Self.read, toByteOffset: word, as: Read.self)
        pointer.storeBytes(of: Self.write, toByteOffset: word * 2, as: Write.self)
    }

    deinit {
        pointer.deallocate()
        buffer.deallocate()
    }

    /// Write what's buffered.
    ///
    /// - Returns: Whether every byte written so far reached the file.
    @discardableResult
    func flush() -> Bool {
        guard !failed else { return false }
        if pending > 0, !Self.transfer(pending, { done, left in Darwin.write(descriptor, buffer + done, left) }) {
            failed = true
        }
        pending = 0
        return !failed
    }

    /// Read `count` items of `size` bytes, as `fread` does.
    private static let read: Read = { destination, size, count, user in
        guard let destination, let user, let total = bytes(size, count) else { return 0 }
        return Unmanaged<YaraStream>.fromOpaque(user).takeUnretainedValue().read(into: destination, total) / size
    }

    /// Write `count` items of `size` bytes, as `fwrite` does.
    private static let write: Write = { source, size, count, user in
        guard let source, let user, let total = bytes(size, count) else { return 0 }
        return Unmanaged<YaraStream>.fromOpaque(user).takeUnretainedValue().write(from: source, total) ? count : 0
    }

    /// `size` times `count`, when both are above zero and the product fits.
    ///
    /// - Parameters:
    ///   - size: The size of an item.
    ///   - count: How many items.
    /// - Returns: The bytes, or `nil`.
    private static func bytes(_ size: Int, _ count: Int) -> Int? {
        guard size > 0, count > 0 else { return nil }
        let (total, overflow) = size.multipliedReportingOverflow(by: count)
        return overflow ? nil : total
    }

    /// Hand over up to `total` bytes, from the buffer and then the file.
    ///
    /// - Parameters:
    ///   - destination: Where they go.
    ///   - total: How many.
    /// - Returns: How many were handed over, fewer at the file's end or on an error.
    private func read(into destination: UnsafeMutableRawPointer, _ total: Int) -> Int {
        var done = 0
        while done < total, !failed {
            if start == end {
                let filled = Self.retrying { Darwin.read(descriptor, buffer, Self.capacity) }
                guard filled > 0 else {
                    failed = filled < 0
                    break
                }
                (start, end) = (0, filled)
            }
            let moved = min(end - start, total - done)
            (destination + done).copyMemory(from: buffer + start, byteCount: moved)
            start += moved
            done += moved
        }
        return done
    }

    /// Buffer `total` bytes, flushing when the buffer is full. A run larger than the buffer goes straight to the file.
    ///
    /// - Parameters:
    ///   - source: The bytes.
    ///   - total: How many.
    /// - Returns: Whether they were taken.
    private func write(from source: UnsafeRawPointer, _ total: Int) -> Bool {
        guard !failed else { return false }
        if pending + total > Self.capacity, !flush() { return false }
        guard total < Self.capacity else {
            failed = !Self.transfer(total) { done, left in Darwin.write(descriptor, source + done, left) }
            return !failed
        }
        (buffer + pending).copyMemory(from: source, byteCount: total)
        pending += total
        return true
    }

    /// Move `total` bytes in as many system calls as it takes.
    ///
    /// - Parameters:
    ///   - total: How many.
    ///   - step: One write of the bytes left, given how many are done.
    /// - Returns: Whether all of them moved.
    private static func transfer(_ total: Int, _ step: (Int, Int) -> Int) -> Bool {
        var done = 0
        while done < total {
            let moved = retrying { step(done, total - done) }
            guard moved > 0 else { return false }
            done += moved
        }
        return true
    }

    /// A system call, again while a signal interrupts it.
    ///
    /// - Parameter call: The call.
    /// - Returns: What it returned.
    private static func retrying(_ call: () -> Int) -> Int {
        var result = call()
        while result < 0 && errno == EINTR { result = call() }
        return result
    }
}
