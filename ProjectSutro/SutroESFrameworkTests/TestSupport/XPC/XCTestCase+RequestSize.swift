//
//  XCTestCase+RequestSize.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Requests at the size limit
extension XPCRequest {
    /// The request's JSON with spaces after it, to exactly `size` bytes: still the same request, so only its size can
    /// turn it away.
    ///
    /// - Parameter size: The size, at least the request's own JSON.
    /// - Returns: The padded JSON.
    func padded(to size: Int) -> Data {
        let json = encoded()
        precondition(json.count <= size, "The request is \(json.count) bytes, more than \(size)")
        return json + Data(repeating: UInt8(ascii: " "), count: size - json.count)
    }
}

extension XCTestCase {
    /// Assert that each request, padded to exactly its type's ``XPCRequest/maximumSize``, reads as itself, and that one
    /// byte more is turned away as too large, with `refusal`, though it's still valid JSON.
    ///
    /// - Parameters:
    ///   - requests: The requests, such as one for each operation.
    ///   - refusal: The whole error text, such as "The request is larger than 64 KiB.".
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    func assertSizeLimit<Request: XPCRequest & Equatable>(_ requests: [Request], refusal: String,
                                                          file: StaticString = #filePath, line: UInt = #line) {
        let limit = Request.maximumSize
        for request in requests {
            let name = String(decoding: request.encoded().prefix(48), as: UTF8.self)
            XCTAssertEqual(try? Request.decode(request.padded(to: limit)), request, "\(name) at \(limit) bytes",
                           file: file, line: line)
            let over = request.padded(to: limit + 1)
            XCTAssertNoThrow(try JSONSerialization.jsonObject(with: over), name, file: file, line: line)
            XCTAssertEqual(thrown(XPCRequestError.self) { try Request.decode(over) }, .invalid(refusal),
                           "\(name) at \(limit + 1) bytes", file: file, line: line)
        }
    }
}
