//
//  CompletionPlacementTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Completion placement
/// Pins where the predicate editor's completion list goes: under the line, over it near the bottom of the screen, left
/// of the right edge, inside the visible frame of the screen the line is on (never the menu bar or the Dock), and as
/// few rows as it takes to fit.
///
/// - Author: Brandon Dalton
final class CompletionPlacementTests: XCTestCase {
    /// A 1440 × 900 display at the origin, with a 25 point menu bar and an 80 point Dock at the bottom.
    private let main = CompletionPlacement.Screen(frame: CGRect(x: 0, y: 0, width: 1440, height: 900),
                                                  visibleFrame: CGRect(x: 0, y: 80, width: 1440, height: 795))
    /// A 1920 × 1080 display to the right of `main`, its menu bar only (macOS shows one on every display).
    private let right = CompletionPlacement.Screen(frame: CGRect(x: 1440, y: -180, width: 1920, height: 1080),
                                                   visibleFrame: CGRect(x: 1440, y: -180, width: 1920, height: 1055))
    /// The list at its usual size: eight rows and a footer.
    private let list = CGSize(width: 400, height: 260)

    /// - Parameters:
    ///   - x: The line's left edge.
    ///   - y: The line's bottom.
    /// - Returns: A line of 12 point text, as `firstRect(forCharacterRange:actualRange:)` gives for an empty range.
    private func line(x: CGFloat, y: CGFloat) -> CGRect {
        CGRect(x: x, y: y, width: 0, height: 16)
    }

    /// - Parameters:
    ///   - placement: Where a list went.
    ///   - visibleFrame: The visible frame it must stay in.
    private func assertOnScreen(_ placement: CompletionPlacement, in visibleFrame: CGRect,
                                file: StaticString = #filePath, line: UInt = #line) {
        let inset = visibleFrame.insetBy(dx: CompletionPlacement.margin, dy: CompletionPlacement.margin)
        XCTAssertTrue(inset.contains(placement.frame), "\(placement.frame) is outside \(inset)", file: file,
                      line: line)
    }

    /// With room under the line, the list goes there, its left edge moved by the offset.
    func testUnderTheLine() {
        let typed = line(x: 300, y: 600)
        let placement = CompletionPlacement(size: list, at: typed, offset: -28, in: main.visibleFrame)
        XCTAssertFalse(placement.isAbove)
        XCTAssertEqual(placement.origin, CGPoint(x: 272, y: 600 - CompletionPlacement.gap - list.height))
        assertOnScreen(placement, in: main.visibleFrame)
    }

    /// Near the bottom, where the Dock is, the list goes over the line instead of under the Dock.
    func testOverTheLineAboveTheDock() {
        let typed = line(x: 300, y: 200)
        let placement = CompletionPlacement(size: list, at: typed, in: main.visibleFrame)
        XCTAssertTrue(placement.isAbove)
        XCTAssertEqual(placement.origin.y, typed.maxY + CompletionPlacement.gap)
        assertOnScreen(placement, in: main.visibleFrame)
    }

    /// Room for the list under the line keeps it there, even when there's more room over it.
    func testUnderWhenItFitsThoughOverIsRoomier() {
        let typed = line(x: 300, y: 400)
        let placement = CompletionPlacement(size: list, at: typed, in: main.visibleFrame)
        XCTAssertFalse(placement.isAbove)
        assertOnScreen(placement, in: main.visibleFrame)
    }

    /// Near the right edge, the list moves left to end at it.
    func testLeftOfTheRightEdge() {
        let typed = line(x: 1300, y: 600)
        let placement = CompletionPlacement(size: list, at: typed, offset: -28, in: main.visibleFrame)
        XCTAssertEqual(placement.frame.maxX, main.visibleFrame.maxX - CompletionPlacement.margin)
        assertOnScreen(placement, in: main.visibleFrame)
    }

    /// Near the bottom right corner, the list goes over the line and left of the edge.
    func testBottomRightCorner() {
        let typed = line(x: 1430, y: 90)
        let placement = CompletionPlacement(size: list, at: typed, offset: -28, in: main.visibleFrame)
        XCTAssertTrue(placement.isAbove)
        assertOnScreen(placement, in: main.visibleFrame)
    }

    /// Near the left edge, the offset doesn't take the list past it.
    func testRightOfTheLeftEdge() {
        let typed = line(x: 10, y: 600)
        let placement = CompletionPlacement(size: list, at: typed, offset: -28, in: main.visibleFrame)
        XCTAssertEqual(placement.origin.x, main.visibleFrame.minX + CompletionPlacement.margin)
        assertOnScreen(placement, in: main.visibleFrame)
    }

    /// A line under the menu bar's height can't put the list behind it: over the line there's no room, so it goes
    /// under, inside the visible frame.
    func testUnderTheMenuBar() {
        let typed = line(x: 300, y: 860)
        let placement = CompletionPlacement(size: list, at: typed, in: main.visibleFrame)
        XCTAssertFalse(placement.isAbove)
        assertOnScreen(placement, in: main.visibleFrame)
    }

    /// A window dragged partly off the bottom of the screen puts the line under the visible frame: the list still
    /// shows inside it.
    func testLineOffTheBottom() {
        let typed = line(x: 300, y: -40)
        let visible = CompletionPlacement.visibleFrame(at: typed, on: [main, right], fallback: .zero)
        let placement = CompletionPlacement(size: list, at: typed, in: visible)
        XCTAssertEqual(visible, main.visibleFrame)
        assertOnScreen(placement, in: main.visibleFrame)
    }

    /// A window dragged partly off the right of the last screen puts the line past it: the list shows on that screen.
    func testLineOffTheRight() {
        let typed = line(x: 3500, y: 300)
        let visible = CompletionPlacement.visibleFrame(at: typed, on: [main, right], fallback: .zero)
        let placement = CompletionPlacement(size: list, at: typed, offset: -28, in: visible)
        XCTAssertEqual(visible, right.visibleFrame)
        assertOnScreen(placement, in: right.visibleFrame)
    }

    /// A line on the second display places the list in that display's visible frame, not the main one's.
    func testSecondDisplay() {
        let typed = line(x: 1500, y: -100)
        let visible = CompletionPlacement.visibleFrame(at: typed, on: [main, right], fallback: .zero)
        XCTAssertEqual(visible, right.visibleFrame)
        let placement = CompletionPlacement(size: list, at: typed, offset: -28, in: visible)
        XCTAssertTrue(placement.isAbove)
        assertOnScreen(placement, in: right.visibleFrame)
    }

    /// A line in the gap a display arrangement leaves between screens goes with the nearest one.
    func testNearestDisplay() {
        let below = CompletionPlacement.Screen(frame: CGRect(x: 0, y: -1080, width: 1440, height: 900),
                                               visibleFrame: CGRect(x: 0, y: -1080, width: 1440, height: 875))
        let typed = line(x: 700, y: -170)
        XCTAssertEqual(CompletionPlacement.visibleFrame(at: typed, on: [main, below], fallback: .zero),
                       below.visibleFrame)
    }

    /// With no displays, the fallback is used.
    func testNoDisplays() {
        let fallback = CGRect(x: 0, y: 0, width: 800, height: 600)
        XCTAssertEqual(CompletionPlacement.visibleFrame(at: line(x: 1, y: 1), on: [], fallback: fallback), fallback)
    }

    /// Full screen, the visible frame is the whole display: the list may use the bottom edge, but not pass it.
    func testFullScreen() {
        let full = CompletionPlacement.Screen(frame: main.frame, visibleFrame: main.frame)
        let typed = line(x: 1400, y: 270)
        let placement = CompletionPlacement(size: list, at: typed, offset: -28, in: full.visibleFrame)
        XCTAssertFalse(placement.isAbove)
        XCTAssertEqual(placement.origin.y, typed.minY - CompletionPlacement.gap - list.height)
        assertOnScreen(placement, in: full.visibleFrame)
    }

    /// A list taller than either side's room keeps its top on screen.
    func testTallerThanTheScreen() {
        let tall = CGSize(width: 400, height: 2000)
        let placement = CompletionPlacement(size: tall, at: line(x: 300, y: 500), in: main.visibleFrame)
        XCTAssertEqual(placement.frame.maxY, main.visibleFrame.maxY - CompletionPlacement.margin)
    }

    /// The room on the roomier side of the line, nothing when the line is off screen.
    func testMaximumHeight() {
        let gap = CompletionPlacement.gap, margin = CompletionPlacement.margin, visible = main.visibleFrame
        XCTAssertEqual(CompletionPlacement.maximumHeight(at: line(x: 0, y: 300), in: visible),
                       visible.maxY - margin - 316 - gap)
        XCTAssertEqual(CompletionPlacement.maximumHeight(at: line(x: 0, y: 700), in: visible),
                       700 - gap - visible.minY - margin)
        XCTAssertEqual(CompletionPlacement.maximumHeight(at: line(x: 0, y: 2000), in: visible), 2000 - gap - 84)
        XCTAssertEqual(CompletionPlacement.maximumHeight(at: CGRect(x: 0, y: 0, width: 0, height: 5000), in: visible),
                       0)
    }

    /// Rows come off a list too tall for its room, a whole row at a time, down to one.
    func testRows() {
        XCTAssertEqual(CompletionPlacement.rows(8, measuring: 260, rowHeight: 23, within: 300), 8)
        XCTAssertEqual(CompletionPlacement.rows(8, measuring: 260, rowHeight: 23, within: 260), 8)
        XCTAssertEqual(CompletionPlacement.rows(8, measuring: 260, rowHeight: 23, within: 237), 7)
        XCTAssertEqual(CompletionPlacement.rows(8, measuring: 260, rowHeight: 23, within: 236), 6)
        XCTAssertEqual(CompletionPlacement.rows(8, measuring: 260, rowHeight: 23, within: 10), 1)
        XCTAssertEqual(CompletionPlacement.rows(8, measuring: 260, rowHeight: 0, within: 10), 8)
    }

    /// The rows that fit, placed, stay on screen and off the line however close it is to the Dock or the menu bar,
    /// on a tall display and on one short enough to take rows off.
    func testSizedListsStayOnScreen() {
        let pitch: CGFloat = 23, footer: CGFloat = 76
        let short = CGRect(x: 0, y: 0, width: 1440, height: 250)
        var trimmed = false
        for visible in [main.visibleFrame, short] {
            for y in stride(from: visible.minY, through: visible.maxY - 16, by: 7) {
                for x in stride(from: visible.minX, through: visible.maxX, by: 97) {
                    let typed = line(x: x, y: y)
                    let maximum = CompletionPlacement.maximumHeight(at: typed, in: visible)
                    let rows = CompletionPlacement.rows(8, measuring: 8 * pitch + footer, rowHeight: pitch,
                                                        within: maximum)
                    trimmed = trimmed || rows < 8
                    let size = CGSize(width: 400, height: CGFloat(rows) * pitch + footer)
                    let placement = CompletionPlacement(size: size, at: typed, offset: -28, in: visible)
                    assertOnScreen(placement, in: visible)
                    XCTAssertFalse(placement.frame.insetBy(dx: 0, dy: 1).intersects(typed.insetBy(dx: -1, dy: 0)),
                                   "The list at \(placement.frame) covers the line at \(typed)")
                }
            }
        }
        XCTAssertTrue(trimmed, "No line was close enough to an edge to take rows off")
    }
}
