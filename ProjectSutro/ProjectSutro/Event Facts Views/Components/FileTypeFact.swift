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

    /// What the type is called, and what's shown on hover.
    private var name: (text: String, help: String) {
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
