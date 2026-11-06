//
//  CommandLineAccessSection.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings ▸ Command Line ▸ Without sudo
/// Two switches for using `macmonitor` without `sudo` (``CommandLineAccess``): streaming, and changing the saved mute
/// set too, which needs the first. Both are off by default, and any Mac Monitor that controls the event stream may
/// flip them, with no password.
///
/// The copy says plainly what turning it on exposes, since any user on the Mac, and any process they run, could then
/// read every process's events.
struct CommandLineAccessSection: View {
    @ObservedObject var model: CommandLineAccessModel
    /// Sends changes to the Security Extension.
    let manager: EndpointSecurityManager

    var body: some View {
        SettingsSection(title: "Without sudo") {
            VStack(alignment: .leading, spacing: 0) {
                row("Stream without sudo",
                    detail: "macmonitor stream, and mute list and export, run for any user on this Mac, "
                        + "administrator or not, without sudo.",
                    isOn: binding(on: .streaming, off: .rootOnly))
                Divider()
                row("Also change the saved mute set without sudo",
                    detail: "Mute changes are persistent: Mac Monitor and every stream follow them.",
                    isOn: binding(on: .streamingAndMuting, off: .streaming))
                    .disabled((model.access ?? .rootOnly) < .streaming)
                if (model.access ?? .rootOnly) > .rootOnly {
                    Callout(title: "Any user can read every process's events", text: Self.exposure)
                }
                Text(Self.enforcement)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(EdgeInsets(top: 8, leading: 14, bottom: 12, trailing: 14))
            }
            .disabled(model.access == nil || model.isChanging)
        }
        .onAppear { model.refresh(through: manager) }
        .alert("Command line tool", isPresented: Binding(get: { model.failure != nil },
                                                          set: { if !$0 { model.failure = nil } }),
               actions: { Button("OK", role: .cancel, action: {}) },
               message: { Text(model.failure ?? "") })
    }

    /// What turning it on exposes.
    static let exposure = "Any user on this Mac, standard or administrator, and any program they run, including "
        + "scripts and malware, can read the events Mac Monitor sees for every process, such as command line arguments "
        + "and file paths, without a password."

    /// Who decides, and when a change applies.
    static let enforcement = "Mac Monitor's Security Extension keeps and enforces this, and only accepts its own "
        + "signed macmonitor. Like the saved mute set, any user's Mac Monitor can change it while it records or "
        + "nothing does. Turning it off applies to the next stream: streams already running keep going until they "
        + "stop."

    /// A switch with what it means. The label takes the row's width, so every switch lines up at the trailing edge
    /// whatever its text's length.
    ///
    /// - Parameters:
    ///   - title: What it does.
    ///   - detail: What that means.
    ///   - isOn: The switch's state.
    /// - Returns: The row.
    private func row(_ title: String, detail: String, isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                Text(detail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .toggleStyle(.switch)
        .padding(.vertical, 10)
        .padding(.horizontal, 14)
    }

    /// A switch that's on at `on` or wider, and asks for `on` or `off` when flipped.
    ///
    /// - Parameters:
    ///   - on: The level the switch turns on.
    ///   - off: The level it falls back to.
    /// - Returns: The binding.
    private func binding(on: CommandLineAccess, off: CommandLineAccess) -> Binding<Bool> {
        Binding(get: { (model.access ?? .rootOnly) >= on },
                set: { model.change(to: $0 ? on : off, through: manager) })
    }
}
