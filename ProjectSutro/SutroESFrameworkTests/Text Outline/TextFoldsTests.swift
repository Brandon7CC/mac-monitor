//
//  TextFoldsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Folds
/// Pins ``TextFolds``: which folds are shown, how offsets map between the text and the text shown, and the pieces a
/// view builds the text shown from.
final class TextFoldsTests: XCTestCase {
    /// A record whose `b` and `d` objects fold, and `c` inside `b`.
    private let text = "{\n  \"a\" : 1,\n  \"b\" : {\n    \"c\" : {\n      \"x\" : 2\n    }\n  },\n"
        + "  \"d\" : [\n    3\n  ]\n}"

    /// The folds of an object or array, from its open bracket through its close.
    ///
    /// - Parameter keys: The keys of the containers to fold.
    /// - Returns: The folds, with each container's summary as its placeholder.
    private func folds(_ keys: [String]) -> [TextFolds.Fold] {
        let outline = JSONOutline(text)
        return keys.map { key in
            let container = outline.containers.first { outline.values[$0.value].keyPath == key }!
            return TextFolds.Fold(range: outline.values[container.value].range, placeholder: container.summary)
        }
    }

    /// - Parameter folds: Folds.
    /// - Returns: The text they show, built from their pieces.
    private func shown(_ folds: TextFolds) -> String {
        let string = text as NSString
        return folds.pieces(of: NSRange(location: 0, length: string.length)).map { piece in
            switch piece {
            case .text(let range): return string.substring(with: range)
            case .fold(let index): return folds.shown[index].placeholder
            }
        }.joined()
    }

    /// - Parameter folds: Folds.
    /// - Returns: Each shown fold's placeholder range in the text shown, worked out from the folds before it.
    private func placeholders(_ folds: TextFolds) -> [NSRange] {
        var removed = 0
        return folds.shown.map { fold in
            defer { removed += fold.range.length - fold.placeholder.utf16.count }
            return NSRange(location: fold.range.location - removed, length: fold.placeholder.utf16.count)
        }
    }

    /// Only the outermost folds are shown, in order, and empty or overlapping ones are left out.
    func testShownFolds() {
        let folds = self.folds(["b.c", "d", "b"])
        let shown = TextFolds(folds).shown
        XCTAssertEqual(shown.map(\.placeholder), ["{ 1 key }", "[ 1 item ]"])
        XCTAssertEqual(shown, [folds[2], folds[1]])
        let overlapping = TextFolds([.init(range: NSRange(location: 2, length: 4), placeholder: "x"),
                                     .init(range: NSRange(location: 5, length: 4), placeholder: "y"),
                                     .init(range: NSRange(location: 9, length: 0), placeholder: "z")])
        XCTAssertEqual(overlapping.shown.map(\.placeholder), ["x"])
        XCTAssertEqual(TextFolds.none.shown, [])
    }

    /// The text shown is the text with each shown fold's range replaced by its placeholder.
    func testPiecesBuildTheTextShown() {
        let folds = TextFolds(self.folds(["b", "d"]))
        XCTAssertEqual(shown(folds), "{\n  \"a\" : 1,\n  \"b\" : { 1 key },\n  \"d\" : [ 1 item ]\n}")
        XCTAssertEqual(shown(.none), text)
        let b = folds.shown[0].range
        XCTAssertEqual(folds.pieces(of: b), [.fold(0)])
        XCTAssertEqual(folds.pieces(of: NSRange(location: 0, length: 0)), [])
        let around = NSRange(location: b.location - 2, length: b.length + 4)
        XCTAssertEqual(folds.pieces(of: around), [.text(NSRange(location: around.location, length: 2)), .fold(0),
                                                  .text(NSRange(location: NSMaxRange(b), length: 2))])
    }

    /// Offsets outside folds map to the same character and back. A hidden one maps to its placeholder's start, and
    /// one in a placeholder to its fold's start, a placeholder's end to its fold's end.
    func testOffsetsMapBothWays() {
        let folds = TextFolds(self.folds(["b", "d"]))
        let original = text as NSString, display = shown(folds) as NSString, placeholders = self.placeholders(folds)
        for offset in 0...original.length {
            if let index = folds.fold(hiding: offset) {
                XCTAssertEqual(folds.shown(offset), placeholders[index].location, "\(offset)")
                continue
            }
            let mapped = folds.shown(offset)
            XCTAssertEqual(folds.original(mapped), offset, "\(offset)")
            if offset < original.length {
                XCTAssertEqual(display.character(at: mapped), original.character(at: offset), "\(offset)")
            }
        }
        XCTAssertEqual(folds.shown(original.length), display.length)
        for index in folds.shown.indices {
            let placeholder = placeholders[index], range = folds.shown[index].range
            XCTAssertEqual(display.substring(with: placeholder), folds.shown[index].placeholder)
            for offset in placeholder.location..<NSMaxRange(placeholder) {
                XCTAssertEqual(folds.original(offset), range.location)
                XCTAssertEqual(folds.fold(atShown: offset), index)
            }
            XCTAssertNil(folds.fold(atShown: NSMaxRange(placeholder)))
            XCTAssertEqual(folds.original(NSMaxRange(placeholder)), NSMaxRange(range))
            XCTAssertEqual(folds.shown(range), placeholder)
            XCTAssertEqual(folds.original(placeholder), range)
            XCTAssertEqual(folds.fold(hiding: range.location), index)
            XCTAssertNil(folds.fold(hiding: NSMaxRange(range)))
        }
        XCTAssertNil(folds.fold(atShown: 0))
        XCTAssertEqual(TextFolds.none.shown(7), 7)
        XCTAssertEqual(TextFolds.none.original(7), 7)
    }
}
