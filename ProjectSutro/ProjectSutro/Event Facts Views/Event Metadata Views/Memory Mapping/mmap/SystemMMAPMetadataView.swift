//
//  SystemMMAPMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemMMAPMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESMMapEvent {
        esSystemEvent.event.mmap!
    }
    
    private var sourcePath: String {
        event.source.path ?? "Unknown"
    }
    
    /// Stored by bit pattern, shown unsigned as Endpoint Security reports it
    private var filePos: UInt64 {
        UInt64(bitPattern: event.file_pos)
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.mmap != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            SystemEventTypeLabel(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **File path mapped:**")
                        GroupBox {
                            Text("`\(sourcePath)`")
                                .lineLimit(10)
                        }
                    }
                    
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
                    
                    HStack {
                        Text("\u{2022} **File offset/position:**")
                        GroupBox {
                            Text("`\(filePos)`")
                                .lineLimit(10)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            
            Divider()
            
            Label("**Context items**", systemImage: "folder.badge.plus").font(.title2).padding([.leading], 5.0)
            GroupBox {
                HStack {
                    Button("**Audit tokens**") {
                        showAuditTokens.toggle()
                    }
                }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
            }
        }.sheet(isPresented: $showAuditTokens) {
            AuditTokenView(
                audit_token: esSystemEvent.process.audit_token_string,
                responsible_audit_token: esSystemEvent.process.responsible_audit_token_string,
                parent_audit_token: esSystemEvent.process.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
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
