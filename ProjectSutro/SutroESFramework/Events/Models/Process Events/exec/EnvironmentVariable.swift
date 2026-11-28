//
//  EnvironmentVariable.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Environment variable
/// One variable of an exec's environment, split into a name and a value at its first "=", as Event Facts' Environment
/// section shows it.
///
/// A variable without "=" is a name with an empty value. Two variables can share a name, and both are kept, so each
/// is identified by its position.
public struct EnvironmentVariable: Identifiable, Equatable {
    /// The variable's position in the environment.
    public let id: Int
    /// The variable as the process got it, such as `PATH=/usr/bin:/bin`.
    public let variable: String
    /// The text before the first "=", or the whole variable without one.
    public let name: String
    /// The text after the first "=", which can hold more of them.
    public let value: String

    /// - Parameters:
    ///   - variable: The variable as the process got it.
    ///   - position: Its position in the environment.
    public init(_ variable: String, at position: Int) {
        id = position
        self.variable = variable
        // The kernel splits at the first "=" byte. A Character can join "=" with a combining mark after it.
        let scalars = variable.unicodeScalars
        if let equals = scalars.firstIndex(of: "=") {
            name = String(scalars[..<equals])
            value = String(scalars[scalars.index(after: equals)...])
        } else {
            name = variable
            value = ""
        }
    }

    /// - Parameter env: The environment's entries, in order.
    /// - Returns: Each entry split into its name and value, in order.
    public static func variables(in env: [String]) -> [EnvironmentVariable] {
        env.enumerated().map { EnvironmentVariable($0.element, at: $0.offset) }
    }

    /// The variables whose name or value contains some text, ignoring case.
    ///
    /// - Parameters:
    ///   - text: The text. Its leading and trailing whitespace is ignored, and empty text matches every variable.
    ///   - variables: The variables, in order.
    /// - Returns: The matching variables, in order.
    public static func matching(_ text: String, in variables: [EnvironmentVariable]) -> [EnvironmentVariable] {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return variables }
        return variables.filter {
            $0.name.localizedCaseInsensitiveContains(text) || $0.value.localizedCaseInsensitiveContains(text)
        }
    }
}
