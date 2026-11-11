//
//  NSColor+Appearance.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import AppKit
import SwiftUI


// MARK: - Colors by appearance
extension NSColor {
    /// - Parameter hex: The color as 0xRRGGBB, in sRGB.
    /// - Returns: The color.
    static func hex(_ hex: Int) -> NSColor {
        NSColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
                blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }

    /// - Parameters:
    ///   - light: The color in light mode.
    ///   - dark: In dark mode.
    /// - Returns: A color that follows the appearance.
    static func appearance(light: NSColor, dark: NSColor) -> NSColor {
        NSColor(name: nil) { $0.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light }
    }
}


extension Color {
    /// - Parameters:
    ///   - light: The color in light mode.
    ///   - dark: In dark mode.
    /// - Returns: A color that follows the appearance.
    static func appearance(light: NSColor, dark: NSColor) -> Color {
        Color(nsColor: .appearance(light: light, dark: dark))
    }
}
