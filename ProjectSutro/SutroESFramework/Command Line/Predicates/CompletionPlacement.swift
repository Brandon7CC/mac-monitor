//
//  CompletionPlacement.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import CoreGraphics


// MARK: - Completion placement
/// Where the predicate editor's completion list goes, as macOS places one: under the line being typed, over it when
/// there isn't room under it, moved left when it would pass the screen's right edge, and never past the edges of the
/// screen's visible frame, which leaves out the menu bar and the Dock.
///
/// Every rectangle is in screen coordinates, with y growing up, as AppKit's are.
public struct CompletionPlacement: Equatable, Sendable {
    /// One display: its whole frame, and the part of it that's left once the menu bar and the Dock are taken out.
    public struct Screen: Equatable, Sendable {
        public let frame: CGRect
        public let visibleFrame: CGRect

        /// - Parameters:
        ///   - frame: The display's frame (`NSScreen.frame`).
        ///   - visibleFrame: Its frame without the menu bar and the Dock (`NSScreen.visibleFrame`).
        public init(frame: CGRect, visibleFrame: CGRect) {
            self.frame = frame
            self.visibleFrame = visibleFrame
        }
    }

    /// The space between the line and the list.
    public static let gap: CGFloat = 4
    /// The least space the list keeps from the visible frame's edges.
    public static let margin: CGFloat = 4

    /// The list's frame.
    public let frame: CGRect
    /// Did the list go over the line, there being too little room under it?
    public let isAbove: Bool

    /// The list's origin, its bottom left corner.
    public var origin: CGPoint { frame.origin }

    /// Place a list of a size at a line.
    ///
    /// It goes under the line, unless it doesn't fit there and there's more room over the line. It starts at the
    /// line's left edge, moved by `offset`, and moves left when it would pass the right edge. A list taller or wider
    /// than the visible frame keeps its top and its left edge on screen.
    ///
    /// - Parameters:
    ///   - size: The list's size.
    ///   - line: The line being typed, such as `NSTextView.firstRect(forCharacterRange:actualRange:)` gives.
    ///   - offset: How far right of the line's left edge the list starts: negative to line its text up with the line's.
    ///   - visibleFrame: The visible frame of the screen the line is on (``visibleFrame(at:on:fallback:)``).
    public init(size: CGSize, at line: CGRect, offset: CGFloat = 0, in visibleFrame: CGRect) {
        let bounds = visibleFrame.insetBy(dx: Self.margin, dy: Self.margin)
        let room = Self.room(at: line, in: visibleFrame)
        isAbove = size.height > room.below && room.above > room.below
        let y = isAbove ? line.maxY + Self.gap : line.minY - Self.gap - size.height
        let x = line.minX + offset
        frame = CGRect(x: max(min(x, bounds.maxX - size.width), bounds.minX),
                       y: min(max(y, bounds.minY), bounds.maxY - size.height),
                       width: size.width, height: size.height)
    }

    /// The tallest list that fits under the line or over it, whichever has more room.
    ///
    /// - Parameters:
    ///   - line: The line being typed.
    ///   - visibleFrame: The visible frame of the screen the line is on.
    /// - Returns: The height, never less than zero.
    public static func maximumHeight(at line: CGRect, in visibleFrame: CGRect) -> CGFloat {
        let room = room(at: line, in: visibleFrame)
        return max(room.below, room.above, 0)
    }

    /// How many rows a list shows so it's no taller than it may be, one at least.
    ///
    /// - Parameters:
    ///   - rows: The rows it would show.
    ///   - height: Its height with them.
    ///   - rowHeight: The height each row adds, its spacing included.
    ///   - maximum: The tallest it may be (``maximumHeight(at:in:)``).
    /// - Returns: The rows that fit.
    public static func rows(_ rows: Int, measuring height: CGFloat, rowHeight: CGFloat,
                            within maximum: CGFloat) -> Int {
        guard height > maximum, rowHeight > 0 else { return rows }
        let over = Int(((height - maximum) / rowHeight).rounded(.up))
        return max(1, rows - over)
    }

    /// The visible frame of the screen a line is on: the one holding the line's middle, else the one nearest it, as a
    /// window dragged partly off every screen can put it.
    ///
    /// - Parameters:
    ///   - line: The line being typed.
    ///   - screens: Every display (`NSScreen.screens`).
    ///   - fallback: The visible frame to use when there are no displays, such as the window's screen's.
    /// - Returns: The visible frame.
    public static func visibleFrame(at line: CGRect, on screens: [Screen], fallback: CGRect) -> CGRect {
        let middle = CGPoint(x: line.midX, y: line.midY)
        if let holding = screens.first(where: { $0.frame.contains(middle) }) { return holding.visibleFrame }
        return screens.min { distance(from: middle, to: $0.frame) < distance(from: middle, to: $1.frame) }?
            .visibleFrame ?? fallback
    }

    /// - Parameters:
    ///   - line: The line being typed.
    ///   - visibleFrame: The visible frame of the screen it's on.
    /// - Returns: The room for a list under the line and over it.
    private static func room(at line: CGRect, in visibleFrame: CGRect) -> (below: CGFloat, above: CGFloat) {
        let bounds = visibleFrame.insetBy(dx: margin, dy: margin)
        return (line.minY - gap - bounds.minY, bounds.maxY - line.maxY - gap)
    }

    /// - Parameters:
    ///   - point: A point.
    ///   - rect: A rectangle.
    /// - Returns: The squared distance from the point to the rectangle's nearest point, zero inside it.
    private static func distance(from point: CGPoint, to rect: CGRect) -> CGFloat {
        let dx = max(rect.minX - point.x, 0, point.x - rect.maxX)
        let dy = max(rect.minY - point.y, 0, point.y - rect.maxY)
        return dx * dx + dy * dy
    }
}
