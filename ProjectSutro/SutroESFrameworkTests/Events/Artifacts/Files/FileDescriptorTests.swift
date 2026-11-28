//
//  FileDescriptorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/27/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - File descriptor labels
/// Pins how Event Facts lists an exec's file descriptors: each one's number and type, a pipe's ID, and the earlier
/// descriptor a pipe is shared with.
final class FileDescriptorTests: XCTestCase {
    /// A descriptor as Endpoint Security gives one.
    ///
    /// - Parameters:
    ///   - number: The descriptor's number.
    ///   - type: Its `PROX_FDTYPE_*`.
    ///   - pipe: A pipe's ID.
    /// - Returns: The descriptor.
    private static func descriptor(_ number: Int32, _ type: Int32 = PROX_FDTYPE_PIPE,
                                   pipe: UInt64 = 0) -> FileDescriptor {
        var fd = es_fd_t()
        fd.fd = number
        fd.fdtype = UInt32(type)
        fd.pipe.pipe_id = pipe
        return FileDescriptor(from: fd)
    }

    /// A pipe an earlier descriptor has too names that descriptor, and the list joins the labels with commas.
    func testASharedPipeNamesTheEarlierDescriptor() {
        let fds = [Self.descriptor(0, pipe: 7), Self.descriptor(1, pipe: 8), Self.descriptor(10, pipe: 8)]
        XCTAssertEqual(FileDescriptor.labels(fds), ["0 PIPE 7", "1 PIPE 8", "10 PIPE 8 (same pipe as 1)"])
        XCTAssertEqual(FileDescriptor.list(fds), "0 PIPE 7, 1 PIPE 8, 10 PIPE 8 (same pipe as 1)")
    }

    /// Every later descriptor of a pipe names the first one that has it.
    func testEachLaterDescriptorNamesTheFirst() {
        let fds = [Self.descriptor(1, pipe: 8), Self.descriptor(3, pipe: 8), Self.descriptor(4, pipe: 8)]
        XCTAssertEqual(FileDescriptor.labels(fds),
                       ["1 PIPE 8", "3 PIPE 8 (same pipe as 1)", "4 PIPE 8 (same pipe as 1)"])
    }

    /// A descriptor that isn't a pipe has no ID, and a type Mac Monitor doesn't name keeps its unknown name.
    func testOtherTypes() {
        let fds = [Self.descriptor(3, PROX_FDTYPE_VNODE), Self.descriptor(4, PROX_FDTYPE_SOCKET),
                   Self.descriptor(5, 99)]
        XCTAssertEqual(FileDescriptor.labels(fds), ["3 VNODE", "4 SOCKET", "5 UNKNOWN"])
    }

    /// A pipe's ID is a `uint64_t`, shown unsigned past `Int64.max`.
    func testALargePipeID() {
        XCTAssertEqual(FileDescriptor.list([Self.descriptor(2, pipe: .max)]), "2 PIPE 18446744073709551615")
    }

    /// No descriptors list nothing.
    func testNoDescriptors() {
        XCTAssertEqual(FileDescriptor.list([]), "")
    }

    /// A stored exec's descriptors list as they were captured.
    func testStoredExec() throws {
        let exec = try importRecord(try esloggerExec(parent: (1, 1)))
        let list = withStoredEvent(exec) { message in
            message.event.exec?.fds = [Self.descriptor(0, pipe: 7), Self.descriptor(1, pipe: 7)]
            return FileDescriptor.list(message.event.exec?.fds ?? [])
        }
        XCTAssertEqual(list, "0 PIPE 7, 1 PIPE 7 (same pipe as 0)")
    }
}
