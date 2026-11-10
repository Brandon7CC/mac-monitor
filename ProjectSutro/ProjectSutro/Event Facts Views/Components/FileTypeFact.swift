//
//  FileTypeFact.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/6/26.
//

import SwiftUI
import UniformTypeIdentifiers
import SutroESFramework


// MARK: - File type
/// The type of an event's file, read from its first bytes when the event was recorded: Launch Services' description of
/// it, such as "Mach-O dynamic library", with its type identifier on hover, and a Mach-O's `MH_*` file type beside it.
struct FileTypeFact: View {
    /// The event's `file_type`: a type identifier, or `empty`, `dyld_shared_cache` or `replaced`.
    let identifier: String
    /// The event's `mach_o_type`, such as `MH_DYLIB`.
    let machOType: String?

    /// What a type is called, and what's shown on hover.
    ///
    /// - Parameter identifier: An event's `file_type`.
    /// - Returns: Launch Services' description of it, or what Mac Monitor calls its own, and the help.
    static func name(of identifier: String) -> (text: String, help: String) {
        switch identifier {
        case FileType.empty:
            return ("Empty", "The event's stat of the file says it had 0 bytes (\(identifier)).")
        case FileType.dyldSharedCache:
            return ("dyld shared cache", "A dyld shared cache: its first bytes are dyld_v1 (\(identifier)).")
        case FileType.replaced:
            return ("Replaced", "By the time it was read, another file was at this path: its device or inode differed "
                        + "from the event's, or a symbolic link was on the path (\(identifier)).")
        default:
            return (UTType(identifier)?.localizedDescription ?? identifier, identifier)
        }
    }

    var body: some View {
        let name = Self.name(of: identifier)
        HStack {
            Text("\u{2022} **File type:**")
            GroupBox {
                Text(name.text)
            }.help(name.help)
            if let machOType {
                GroupBox {
                    Text(machOType)
                        .monospaced()
                }.help("The Mach-O header's filetype.")
            }
        }
    }
}


// MARK: - File type badge
/// An event's file type as a small capsule beside the event in a table: a Mach-O's `MH_*` file type, else what the
/// type is called, in the color of the most severe indicator the event matched. Gray for none or Low, orange for
/// Medium, red for High.
struct FileTypeBadge: View {
    /// The event's `file_type`: a type identifier, or one of Mac Monitor's own.
    let identifier: String
    /// The event's `mach_o_type`, such as `MH_DYLIB`.
    let machOType: String?
    /// The most severe indicator the event matched, if it matched one.
    let severity: IndicatorSeverity?

    /// The type of an event's file, read once while the event is known to be there.
    ///
    /// - Parameter message: An event, on its context's queue.
    /// - Returns: Its `file_type` and `mach_o_type`, or `nil` for an event whose file's type wasn't read: only a
    ///   close, a rename and an mmap have one.
    static func type(of message: ESMessage) -> (identifier: String, machOType: String?)? {
        let event = message.event
        guard let identifier = event.close?.file_type ?? event.rename?.file_type ?? event.mmap?.file_type else {
            return nil
        }
        return (identifier, event.close?.mach_o_type ?? event.rename?.mach_o_type ?? event.mmap?.mach_o_type)
    }

    /// The badge's color, by the severity.
    private var color: Color {
        switch severity {
        case .high: return .red
        case .medium: return .orange
        case .low, nil: return .secondary
        }
    }

    var body: some View {
        let name = FileTypeFact.name(of: identifier)
        Text(machOType ?? name.text)
            .font(.system(size: 10, weight: .medium)).monospaced(machOType != nil)
            .lineLimit(1)
            .foregroundStyle(color)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(color.opacity(0.14), in: Capsule())
            .help(machOType.map { "\(name.text), \($0) (\(identifier))" } ?? "\(name.text) (\(name.help))")
            .accessibilityLabel("File type: \(machOType ?? name.text)")
    }
}
