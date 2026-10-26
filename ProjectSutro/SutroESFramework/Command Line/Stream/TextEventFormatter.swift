//
//  TextEventFormatter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Text lines
/// Writes an event as one line for people, `macmonitor`'s output on a terminal:
///
/// ```
/// 14:03:22.123  exec          zsh[4211]  root  /bin/ls -la
/// ```
///
/// The local time to the millisecond, the event's short name, the initiating process's name and ID, its effective
/// user, and Mac Monitor's summary of the event (an exec's command line, an open's path), or else its target path.
/// Every field goes through ``TerminalSafeText/text(_:)``. Only the header is decoded, so text keeps up with far more
/// events than JSONL does.
public struct TextEventFormatter {
    /// The column the event's name is padded to.
    static let nameWidth = 12
    /// The time zone times are shown in.
    public let timeZone: TimeZone
    
    /// - Parameter timeZone: The time zone times are shown in: the Mac's, unless a test picks one.
    public init(timeZone: TimeZone = .current) {
        self.timeZone = timeZone
    }
    
    /// An event's line.
    ///
    /// - Parameter header: The event's header.
    /// - Returns: The line, ending in a newline.
    public func line(for header: EventHeader) -> String {
        let name = TerminalSafeText.text(CommandLineEvents.shortName(header.name))
        let padded = name.count < Self.nameWidth ? name + String(repeating: " ", count: Self.nameWidth - name.count)
            : name
        let process = header.process.path.map { ($0 as NSString).lastPathComponent }.flatMap { $0.isEmpty ? nil : $0 }
            ?? "?"
        let detail = [header.context, header.targetPath].compactMap { $0 }
            .first { !$0.isEmpty && $0 != "Not supported" } ?? ""
        return [clock(header.time), padded, "\(TerminalSafeText.text(process))[\(header.process.pid)]",
                TerminalSafeText.text(header.process.user ?? "-"), TerminalSafeText.text(detail)]
            .joined(separator: "  ") + "\n"
    }
    
    /// An event's `time` as the local time of day, such as "14:03:22.123".
    ///
    /// - Parameter time: The UTC time, as eslogger writes it.
    /// - Returns: The local time to the millisecond, or `time` itself (escaped) if it isn't a UTC time.
    func clock(_ time: String) -> String {
        guard let utc = ESLogger.utcTimespec(from: time) else { return TerminalSafeText.text(time) }
        let offset = timeZone.secondsFromGMT(for: Date(timeIntervalSince1970: TimeInterval(utc.tv_sec)))
        let secondOfDay = ((utc.tv_sec + offset) % 86_400 + 86_400) % 86_400
        /// A number with leading zeros: `power` 100 for two digits, 1,000 for three.
        func digits(_ value: Int, _ power: Int) -> Substring { String(power + value).dropFirst() }
        return "\(digits(secondOfDay / 3_600, 100)):\(digits(secondOfDay / 60 % 60, 100)):"
            + "\(digits(secondOfDay % 60, 100)).\(digits(utc.tv_nsec / 1_000_000, 1_000))"
    }
}
