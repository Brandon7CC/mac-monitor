//
//  SequenceWindow.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Unordered windows
/// An unordered chain's steps as one event sees them: each step's latest time and the event that matched it, with
/// the event's own steps at its own time, so an event a lane hands over late is judged at its time, not the chain's
/// latest.
struct SequenceWindow {
    /// Each step's time, in seconds after the chain's first: minus infinity for none.
    var times: SIMD8<Float>
    /// Which of the chain's events matched each step.
    var events: SIMD8<UInt8>
    /// How many steps the sequence has.
    let steps: Int

    /// Does a window of `within` seconds holding the event hold at least `count` steps, each matched by a different
    /// event? Not with fewer steps matched at all, which is counted first, so a chain that's still short costs a few
    /// comparisons.
    ///
    /// - Parameters:
    ///   - count: How many steps.
    ///   - offset: The event's time, in seconds after the chain's first.
    ///   - within: The window's length.
    /// - Returns: `true` when one does.
    func holds(_ count: Int, around offset: Float, within: Float) -> Bool {
        var matched = 0
        for step in 0..<steps where times[step] > -.infinity { matched += 1 }
        return matched >= count && mostEvents(around: offset, within: within) >= count
    }

    /// The most steps that fit in a window of `within` seconds holding the event, each matched by a different event:
    /// one event that matched two steps counts once. Every window worth trying starts at a step's time, so at most 8
    /// are tried.
    ///
    /// - Parameters:
    ///   - offset: The event's time, in seconds after the chain's first.
    ///   - within: The window's length.
    /// - Returns: How many.
    func mostEvents(around offset: Float, within: Float) -> Int {
        var most = 0
        for start in 0..<steps {
            let begin = times[start]
            guard begin <= offset, offset - begin <= within else { continue }
            most = max(most, events(from: begin, to: begin + within))
        }
        return most
    }

    /// - Parameters:
    ///   - begin: The window's start.
    ///   - end: Its end.
    /// - Returns: How many different events matched the steps whose times are in it.
    private func events(from begin: Float, to end: Float) -> Int {
        var counted: UInt8 = 0, count = 0
        for step in 0..<steps where times[step] >= begin && times[step] <= end {
            let repeated = (0..<step).contains { counted & 1 << $0 != 0 && events[$0] == events[step] }
            guard !repeated else { continue }
            counted |= 1 << step
            count += 1
        }
        return count
    }
}
