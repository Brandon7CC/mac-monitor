//
//  IndicatorRequestTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Indicator requests and replies
/// Pins the JSON Mac Monitor, `macmonitor` and the Security Extension exchange about the Mac's indicator set: round
/// trips with every severity, strict requests, and what an older or newer peer makes of the other's messages.
final class IndicatorRequestTests: XCTestCase {
    /// Requests and a reply read back as they were written, severities included.
    func testRequestsAndRepliesRoundTrip() throws {
        let high = ownIndicator("High", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#, severity: .high)
        let low = ownIndicator("Low", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_OPEN""#, severity: .low)
        let requests = [IndicatorRequest(.list), IndicatorRequest(.add, indicators: [high, low]),
                        IndicatorRequest(.remove, ids: [high.id]),
                        IndicatorRequest(.setEnabled, ids: [low.id], enabled: false),
                        IndicatorRequest(.replace, indicators: Indicator.defaults),
                        IndicatorRequest(.update, indicators: [high], fields: [.predicate, .severity])]
        for request in requests {
            XCTAssertEqual(try IndicatorRequest.decode(request.encoded()), request, request.operation.rawValue)
        }
        let reply = IndicatorReply(status: .refused, changed: true, indicators: [high, low],
                                   problems: [IndicatorReply.Problem(id: low.id, reason: "No.")],
                                   failure: "Refused.", notice: "Read-only.", access: .list, readOnly: true)
        let read = try XCTUnwrap(IndicatorReply.decode(reply.encoded()))
        XCTAssertEqual(read, reply)
        XCTAssertEqual(read.indicators.map(\.severity), [.high, .low])
        XCTAssertTrue(read.readOnly)
    }

    /// A reply missing everything but its version and status still reads, writable when it doesn't say. An unknown
    /// status reads as unsupported, an unknown access as none, and an indicator or problem that doesn't read is left
    /// out, the rest kept.
    func testRepliesReadForward() throws {
        XCTAssertEqual(IndicatorReply.decode(Data(#"{"version": 1, "status": "ok"}"#.utf8)),
                       IndicatorReply(status: .ok, indicators: []))
        XCTAssertNil(IndicatorReply.decode(Data(#"{"status": "ok"}"#.utf8)))
        let newer = Data("""
            {"version": 2, "status": "renamed", "access": "guest", "extra": 1,
             "indicators": [{"name": "Kept", "predicate": "TRUEPREDICATE"},
                            {"name": "Sequence", "predicate": "TRUEPREDICATE", "kind": "sequence"}, 7],
             "problems": [{"id": "\(UUID().uuidString)", "reason": "Why."}, {"reason": "No identity."}]}
            """.utf8)
        let read = try XCTUnwrap(IndicatorReply.decode(newer))
        XCTAssertEqual(read.status, .unsupported)
        XCTAssertNil(read.access)
        XCTAssertFalse(read.readOnly)
        XCTAssertEqual(read.indicators.map(\.name), ["Kept"])
        XCTAssertEqual(read.problems.map(\.reason), ["Why."])
    }

    /// A newer version, an unknown operation or an unknown field is unsupported, not invalid. Missing indicators,
    /// identities and fields mean none. A Security Extension whose operations stop before `update` answers one as
    /// unsupported too, so `macmonitor` and Settings say to update it.
    func testNewerRequestsAreUnsupported() throws {
        let texts = [#"{"version": 2, "operation": "list"}"#, #"{"version": 1, "operation": "sequence"}"#,
                     #"{"version": 1, "operation": "update", "fields": ["severity", "weight"]}"#]
        for text in texts {
            let error = thrown(XPCRequestError.self) { try IndicatorRequest.decode(Data(text.utf8)) }
            XCTAssertEqual(error?.status(as: IndicatorReply.Status.self), .unsupported, text)
        }
        let field = thrown(XPCRequestError.self) { try IndicatorRequest.decode(Data(texts[2].utf8)) }
        XCTAssertEqual(field?.description, "This Security Extension doesn't know the field “weight”.")
        let bare = Data(#"{"version": 1, "operation": "remove"}"#.utf8)
        XCTAssertEqual(try IndicatorRequest.decode(bare), IndicatorRequest(.remove))

        let update = IndicatorRequest(.update, indicators: [Indicator.defaults[0]], fields: [.severity]).encoded()
        XCTAssertThrowsError(try JSONDecoder().decode(RequestBeforeUpdate.self, from: update)) {
            XCTAssertEqual(($0 as? XPCRequestError)?.status(as: IndicatorReply.Status.self), .unsupported)
        }
        XCTAssertNoThrow(try JSONDecoder().decode(RequestBeforeUpdate.self, from: IndicatorRequest(.add).encoded()))
    }

    /// A request as a Security Extension whose operations stop before `update` reads one.
    private struct RequestBeforeUpdate: Decodable {
        /// The operations before `update`.
        enum Operation: String { case list, add, remove, setEnabled, replace }

        /// The keys it reads first.
        enum CodingKeys: String, CodingKey { case version, operation }

        /// - Parameter decoder: The decoder.
        /// - Throws: ``XPCRequestError`` for an operation it doesn't know.
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let _: (Int, Operation) = try IndicatorRequest.header(of: container, version: .version, name: .operation)
        }
    }

    /// Text that isn't a request, a version below 1, and an indicator that doesn't decode (a field past its cap,
    /// another kind of rule, no predicate), are invalid, and say where.
    func testInvalidRequests() {
        let longName = String(repeating: "n", count: Indicator.Limits.name + 1)
        let texts: [String] = [
            "nope", #"{"operation": "list"}"#, #"{"version": 0, "operation": "list"}"#,
            #"{"version": 1, "operation": "add", "indicators": [{"name": "LONG", "predicate": "TRUEPREDICATE"}]}"#,
            #"{"version": 1, "operation": "add", "indicators": [{"name": "S", "predicate": "1 == 1", "kind": "seq"}]}"#,
            #"{"version": 1, "operation": "replace", "indicators": [{"name": "N"}]}"#,
        ]
        let requests: [Data] = texts.map { Data($0.replacingOccurrences(of: "LONG", with: longName).utf8) }
        for data in requests {
            let error = thrown(XPCRequestError.self) { try IndicatorRequest.decode(data) }
            XCTAssertEqual(error?.status(as: IndicatorReply.Status.self), .invalid)
        }
        let capped = thrown(XPCRequestError.self) { try IndicatorRequest.decode(requests[3]) }
        XCTAssertTrue(capped?.description.contains("indicators.0") == true, capped?.description ?? "")
        XCTAssertTrue(capped?.description.contains("\(Indicator.Limits.name) characters") == true)
        let missing = thrown(XPCRequestError.self) { try IndicatorRequest.decode(requests[5]) }
        XCTAssertTrue(missing?.description.contains("“indicators.0.predicate” is missing") == true,
                      missing?.description ?? "")
    }

    /// A request of every operation, `update` included, padded with spaces to exactly 4 MiB, reads. One byte more is
    /// too large, though it's still the same request.
    func testTheSizeLimitIsExact() {
        let mine = ownIndicator("Mine", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#, severity: .high)
        assertSizeLimit(IndicatorRequest.Operation.allCases.map { operation in
            IndicatorRequest(operation, indicators: [mine], ids: [mine.id], enabled: true, fields: [.severity])
        }, refusal: "The request is larger than 4 MiB.")
    }
}
