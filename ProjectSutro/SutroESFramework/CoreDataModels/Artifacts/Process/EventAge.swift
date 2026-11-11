//
//  EventAge.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation

// MARK: - Ages at an event
/// An age Mac Monitor stores in milliseconds at an event: an executable's at its exec
/// (``ESProcessExecEvent/executable_age_ms``) or a process's (``Process/process_age_ms``), as it's shown.
public enum EventAge {
    /// The age in seconds.
    ///
    /// - Parameter milliseconds: The stored age, or `nil` when it's unknown.
    /// - Returns: The seconds, or `nil` when the age is unknown or negative (the clock stepped back).
    public static func seconds(fromMilliseconds milliseconds: NSNumber?) -> TimeInterval? {
        milliseconds.map { $0.doubleValue / 1000 }.flatMap { $0 >= 0 ? $0 : nil }
    }

    /// The age as text: "3.25s" under a minute, then "4min", "12h", "1 day" and "12 days". The age is first rounded
    /// to the millisecond, as Mac Monitor stores it, and then each unit is rounded down: 59.996 s is "59.99s".
    ///
    /// - Parameter seconds: The age in seconds, or `nil`.
    /// - Returns: The text, or `nil` when the age is `nil`, negative or too large to be one.
    public static func text(seconds: TimeInterval?) -> String? {
        guard let age = seconds, age >= 0, let milliseconds = Int(exactly: (age * 1000).rounded()) else { return nil }
        switch milliseconds {
        case ..<60_000: return String(format: "%d.%02ds", milliseconds / 1000, milliseconds % 1000 / 10)
        case ..<3_600_000: return "\(milliseconds / 60_000)min"
        case ..<86_400_000: return "\(milliseconds / 3_600_000)h"
        default:
            let days = milliseconds / 86_400_000
            return days == 1 ? "1 day" : "\(days) days"
        }
    }
}


// MARK: - Process ages
extension ESMessage {
    /// Seconds from the initiating process's start to the event (``process_age_ms``), or `nil` when it's unknown or
    /// negative. Read from the event, never from the shared ``process`` row, which has no age.
    public var processAge: TimeInterval? { EventAge.seconds(fromMilliseconds: process_age_ms) }

    /// ``processAge`` as text (``EventAge/text(seconds:)``), or `nil`.
    public var processAgeText: String? { EventAge.text(seconds: processAge) }
}

extension ESProcessExecEvent {
    /// Seconds from the new image's process start to the exec (``target_age_ms``), or `nil`. An exec keeps the
    /// process's start time, so it's the age of the process that called `execve`.
    public var targetAge: TimeInterval? { EventAge.seconds(fromMilliseconds: target_age_ms) }

    /// ``targetAge`` as text (``EventAge/text(seconds:)``), or `nil`.
    public var targetAgeText: String? { EventAge.text(seconds: targetAge) }

    /// How long before the exec its executable was created (``executableAge``), such as "3.25s", "4min" or
    /// "12 days", or `nil`.
    public var executableAgeText: String? { EventAge.text(seconds: executableAge) }
}

extension ESProcessForkEvent {
    /// Seconds from the child's start to the fork (``child_age_ms``), or `nil`.
    public var childAge: TimeInterval? { EventAge.seconds(fromMilliseconds: child_age_ms) }

    /// ``childAge`` as text (``EventAge/text(seconds:)``), or `nil`.
    public var childAgeText: String? { EventAge.text(seconds: childAge) }
}

extension ESProcess {
    /// Seconds from the process's start to its event (``process_age_ms``), or `nil`. Only an owned row has an age: read
    /// a shared one's from its event (``ESMessage/processAge``, ``ESProcessExecEvent/targetAge``,
    /// ``ESProcessForkEvent/childAge``).
    public var processAge: TimeInterval? { EventAge.seconds(fromMilliseconds: process_age_ms) }

    /// ``processAge`` as text (``EventAge/text(seconds:)``), or `nil`.
    public var processAgeText: String? { EventAge.text(seconds: processAge) }
}
