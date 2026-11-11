//
//  SystemMMAPMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// What an `mmap` event says: the file mapped, its type, and the protection, flags and offset asked for.
struct SystemMMAPMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.mmap {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "File path mapped", value: event.source.path)

                    /// Read from the file's first bytes when the event was recorded: none when it wasn't read.
                    if let fileType = event.file_type {
                        FileTypeFact(identifier: fileType, machOType: event.mach_o_type)
                    }

                    HStack {
                        Text("\u{2022} **Protection:**")
                        MemoryProtectionFact(protection: event.protection)
                        if let callout = MemoryMappingCallout(protection: event.protection) {
                            MemoryMappingCalloutBadge(callout: callout)
                        }

                        Text("\u{2022} **Max protection:**")
                        MemoryProtectionFact(protection: event.max_protection)
                    }

                    HStack(alignment: .firstTextBaseline) {
                        Text("\u{2022} **Flags:**")
                        MemoryMappingFlagChips(flags: event.flags)
                    }

                    /// Stored by bit pattern, shown unsigned as Endpoint Security reports it.
                    FactRow(name: "File offset/position", value: "\(UInt64(bitPattern: event.file_pos))")
                }
            }
        }
    }
}



// MARK: - Protection and flags
/// A protection in `vmmap`'s notation, such as "r-x", with its `PROT_*` names and value on hover. It's the protection
/// asked for at the check before the mapping is made, so it can differ from what `vmmap` later shows: the kernel adds
/// read to an execute-only request, and strips execute from a writable one on Apple silicon.
struct MemoryProtectionFact: View {
    /// `protection` or `max_protection`.
    let protection: Int32

    var body: some View {
        GroupBox {
            Text(MemoryMappingNames.permissions(protection))
                .monospaced()
        }
        .help(MemoryMappingNames.protection.label(protection))
    }
}

/// What an executable mapping is worth pointing out, beside its protection.
struct MemoryMappingCalloutBadge: View {
    let callout: MemoryMappingCallout

    /// The badge's text and color: orange for executable, red for writable and executable. The event comes from the
    /// check before the mapping is made, so the help says what was asked for, not what the mapping became.
    private var style: (text: String, color: Color, help: String) {
        switch callout {
        case .executable:
            return ("Executable", .orange, "Asked to map the file executable: code, such as a library dyld loads.")
        case .writableAndExecutable:
            return ("Writable and executable", .red,
                    "Asked to map the file writable and executable at once. Apple silicon strips execute from such "
                        + "a mapping or fails it, as Intel does under code signing enforcement, so asking is itself "
                        + "unusual.")
        }
    }

    var body: some View {
        CalloutBadge(text: style.text, color: style.color, help: style.help)
    }
}

/// An mmap's flags, one chip for each named bit in bit order, then the whole value in hex. Chips wrap when there are
/// many. A bit no name covers shows only in the hex.
struct MemoryMappingFlagChips: View {
    /// `flags`.
    let flags: Int32

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(MemoryMappingNames.flags.names(flags), id: \.self) { name in
                Text(name)
                    .font(.caption.monospaced())
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .overlay(Capsule().strokeBorder(Color(nsColor: .separatorColor)))
            }
            Text(MemoryMappingNames.hex(flags))
                .font(.callout.monospaced())
                .foregroundStyle(.secondary)
                .help("flags (\(flags))")
        }
    }
}
