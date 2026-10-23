//
//  SystemDetailsSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Settings ▸ System Details
/// Settings ▸ System Details: this Mac, System Integrity Protection, and the Sensor ID Mac Monitor records with every
/// event.
struct SystemDetailsSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager

    var body: some View {
        SettingsForm(pane: .systemDetails) {
            Section {
                LabeledContent { Text(SystemFacts.macOSVersion) } label: {
                    SettingsIconLabel("macOS", symbol: "desktopcomputer", tint: .blue)
                }
                LabeledContent { Text(SystemFacts.processor) } label: {
                    SettingsIconLabel("Processor", symbol: "cpu", tint: .gray)
                }
                LabeledContent { Text("\(SystemFacts.memoryGB) GB") } label: {
                    SettingsIconLabel("Memory", symbol: "memorychip", tint: .green)
                }
            }
            Section {
                LabeledContent {
                    HStack(spacing: 10) {
                        Label(SystemFacts.sipStatus, systemImage: "circle.fill")
                            .labelStyle(SIPStatusLabelStyle(enabled: SIPStatus.current == .enabled))
                        SettingsCopyButton(text: SystemFacts.sipFlagsText, what: "the SIP flags", title: "Copy Flags")
                    }
                } label: {
                    SettingsIconLabel("Status", detail: SystemFacts.sipSummary, symbol: "lock.shield.fill",
                                      tint: .orange)
                }
                SIPProtectionsGrid()
            } header: {
                Text("System Integrity Protection")
            } footer: {
                Text("Every event records the status as sip_status.").foregroundStyle(.secondary)
            }
            Section {
                LabeledContent {
                    HStack(spacing: 8) {
                        Text(systemExtensionManager.sensorID)
                            .font(.callout.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                        SettingsCopyButton(text: systemExtensionManager.sensorID, what: "the Sensor ID")
                    }
                } label: {
                    SettingsIconLabel("Sensor ID", symbol: "person.text.rectangle", tint: .indigo)
                }
            } footer: {
                Text("A SHA-512 of this Mac's serial number and the console user's name, recorded with every event as "
                     + "sensor_id.").foregroundStyle(.secondary)
            }
        }
    }
}


/// SIP's status as a colored dot before its name: green when it's on, orange when anything is off.
private struct SIPStatusLabelStyle: LabelStyle {
    let enabled: Bool

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) {
            configuration.icon.font(.system(size: 7)).foregroundStyle(enabled ? .green : .orange)
            configuration.title
        }
    }
}


/// Every protection SIP has, two to a row: a dot, its name, its `csr.h` flag, and whether it's on.
private struct SIPProtectionsGrid: View {
    var body: some View {
        LazyVGrid(columns: [GridItem(.flexible(), spacing: 20), GridItem(.flexible())], alignment: .leading,
                  spacing: 8) {
            ForEach(SystemFacts.protections) { protection in
                HStack(spacing: 8) {
                    Circle().fill(protection.isOn ? Color.green : .orange).frame(width: 7, height: 7)
                    VStack(alignment: .leading, spacing: 0) {
                        Text(protection.name).lineLimit(1)
                        Text(protection.flag).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer(minLength: 4)
                    Text(protection.isOn ? "On" : "Off")
                        .foregroundStyle(protection.isOn ? .secondary : .primary)
                }
                .help(protection.flag)
                .accessibilityElement(children: .combine)
            }
        }
        .padding(.vertical, 4)
    }
}


// MARK: - This Mac
/// What System Details shows about this Mac.
enum SystemFacts {
    /// Such as "Version 27.0.1 (Build 26A434)", without "Version ".
    static var macOSVersion: String {
        String(ProcessInfo.processInfo.operatingSystemVersionString.trimmingPrefix("Version "))
    }

    /// The processor's name, such as "Apple M4 Pro".
    static var processor: String {
        var name = [Int8](repeating: 0, count: 128)
        var size = name.count
        sysctlbyname("machdep.cpu.brand_string", &name, &size, nil, 0)
        return String(cString: name)
    }

    /// The memory, in whole gigabytes.
    static var memoryGB: Int {
        var size: UInt64 = 0
        var length = MemoryLayout<UInt64>.size
        sysctlbyname("hw.memsize", &size, &length, nil, 0)
        return Int(size / (1024 * 1024 * 1024))
    }

    /// System Integrity Protection's status, as `csrutil status` names it and every event records it.
    static var sipStatus: String {
        SIPStatus.current.map { $0.rawValue.capitalized } ?? "Unknown"
    }

    /// One SIP protection: on unless the active configuration sets its `CSR_ALLOW_` flag.
    struct Protection: Identifiable {
        let name: String
        /// Its name in `csr.h`, such as `CSR_ALLOW_UNRESTRICTED_FS`.
        let flag: String
        let isOn: Bool
        var id: String { flag }
    }

    /// The protections, in `csr.h`'s bit order, by the names `csr.h` gives their flags.
    static var protections: [Protection] {
        let named = [("Kernel extension signing", "UNTRUSTED_KEXTS"), ("File system protection", "UNRESTRICTED_FS"),
                     ("Task port protection", "TASK_FOR_PID"), ("Kernel debugging", "KERNEL_DEBUGGER"),
                     ("Apple internal", "APPLE_INTERNAL"), ("DTrace restrictions", "UNRESTRICTED_DTRACE"),
                     ("NVRAM protection", "UNRESTRICTED_NVRAM"), ("Device configuration", "DEVICE_CONFIGURATION"),
                     ("Any recovery OS", "ANY_RECOVERY_OS"), ("Kernel extension approval", "UNAPPROVED_KEXTS"),
                     ("Executable policy", "EXECUTABLE_POLICY_OVERRIDE"),
                     ("Authenticated root volume", "UNAUTHENTICATED_ROOT")]
        return named.enumerated().map { bit, protection in
            Protection(name: protection.0, flag: "CSR_ALLOW_" + protection.1,
                       isOn: csr_check(csr_config_t(1 << bit)) != 0)
        }
    }

    /// What the active configuration allows, by the names in `csr.h`: none when SIP is fully on.
    static var sipAllowances: [String] {
        protections.filter { !$0.isOn }.map(\.flag)
    }

    /// The active configuration's bits, as `csr_get_active_config` reports them.
    static var sipConfiguration: UInt32? {
        var configuration: csr_config_t = 0
        return csr_get_active_config(&configuration) == 0 ? configuration : nil
    }

    /// Such as "csr-active-config 0x6f · 6 flags".
    static var sipSummary: String {
        let count = sipAllowances.count
        let flags = "\(count) \(count == 1 ? "flag" : "flags")"
        return sipConfiguration.map { "csr-active-config 0x\(String($0, radix: 16)) · \(flags)" } ?? flags
    }

    /// What Copy Flags copies: the configuration, then each flag it sets, one per line.
    static var sipFlagsText: String {
        ([sipConfiguration.map { "csr-active-config 0x\(String($0, radix: 16))" } ?? "csr-active-config unknown"]
         + sipAllowances).joined(separator: "\n")
    }
}
