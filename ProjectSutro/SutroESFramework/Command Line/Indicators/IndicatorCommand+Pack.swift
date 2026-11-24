//
//  IndicatorCommand+Pack.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation


// MARK: - Indicator packs
/// `macmonitor indicators pack status|check|install|mode`: the signed indicator pack Mac Monitor's own indicators
/// are (``IndicatorBaseline``), and looking for a newer one.
///
/// The Security Extension does the work. It gets a pack from GitHub itself, or is sent a file's bytes, which are read
/// here as the user running `macmonitor`, and checks the signature over them itself: nothing `macmonitor` says about
/// a pack is trusted. Before installing, `install` asks the Security Extension what the pack would change
/// (``IndicatorRequest/Operation/checkPack``), says so, and asks, as `import` does. A pack that wouldn't be installed
/// is refused with the Security Extension's reason, and exits 65. GitHub not answering exits 75.
extension IndicatorCommand {
    /// Run `indicators pack install`.
    ///
    /// - Parameters:
    ///   - path: The signed pack file, `-` for standard input, or `nil` for the newest pack on GitHub.
    ///   - confirmed: Go ahead without asking.
    ///   - completion: Called once, on any thread: success, or why not.
    func installPack(_ path: String?, confirmed: Bool,
                     _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        var file: Data?
        if let path {
            do {
                file = try input(from: path, for: "installed").data
            } catch {
                return completion(.failure(Self.failure(error)))
            }
        }
        let source = path.map { $0 == "-" ? "standard input" : TerminalSafeText.quoted($0) } ?? "GitHub"
        /// Installs the pack, and only the release that was asked about, when one was.
        let install = { [self] (checked: Int?) in
            send(IndicatorRequest(.installPack, pack: file, expecting: checked), completion) { reply in
                reply.changed ? Self.installed(reply, from: source) : Self.newest(reply)
            }
        }
        guard !confirmed else { return install(nil) }
        checking(file, completion) { [self] current, preview in
            guard Self.isNewer(preview, than: current) else {
                return completion(output.writeResult(Data(Self.newest(current).utf8)))
            }
            let release = preview.pack.map { "indicator pack \($0.sequence)" } ?? "the indicator pack"
            ask(about: PendingChange(command: "indicators pack install",
                                     question: "Install \(release) from \(source)?") { _ in preview.indicators },
                then: { install(preview.pack?.sequence) }, otherwise: completion)
        }
    }

    /// Run `indicators pack check`: look on GitHub for a newer pack, and say what installing it would change.
    ///
    /// - Parameters:
    ///   - json: Write JSON rather than text?
    ///   - completion: Called once, on any thread: success, or why not.
    func checkPack(json: Bool, _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        checking(nil, completion) { [self] current, preview in
            let isNewer = Self.isNewer(preview, than: current)
            let effect = IndicatorSetChange(from: current.indicators, to: preview.indicators,
                                            shipped: Set(current.shipped.keys))
            guard json else {
                let text = isNewer ? """
                    Indicator pack \(preview.pack?.sequence ?? 0) is out. \(Self.has(current))
                    \(effect.description)
                    Install it with 'sudo macmonitor indicators pack install'.

                    """ : Self.newest(current)
                return completion(output.writeResult(Data(text.utf8)))
            }
            let object: [String: Any] = [
                "available": isNewer, "current": current.pack?.sequence ?? NSNull(),
                "latest": isNewer ? preview.pack?.sequence ?? NSNull() : NSNull(),
                "added": effect.added, "removed": effect.removed, "changed": effect.changed,
            ]
            completion(output.writeResult(Self.json(object)))
        }
    }

    /// Run `indicators pack status`: which pack this Mac has and what the last look found, without asking GitHub.
    ///
    /// - Parameters:
    ///   - json: Write JSON rather than text?
    ///   - completion: Called once, on any thread: success, or why not.
    func packStatus(json: Bool, _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        listing(completion) { [self] reply in
            guard let pack = reply.pack else { throw CommandLineFailure.olderSecurityExtension }
            completion(output.writeResult(json ? Self.json(Self.statusObject(pack)) : Data(Self.status(pack).utf8)))
        }
    }

    /// List the set, then have the Security Extension check a pack: a file's, or the newest on GitHub.
    ///
    /// - Parameters:
    ///   - file: The pack's file, or `nil` to look on GitHub.
    ///   - completion: Called once, on any thread, if listing, checking or `body` fails.
    ///   - body: Acts on the set as it stands and as installing the pack would leave it. With no newer pack on
    ///     GitHub, the two are the same.
    private func checking(_ file: Data?, _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void,
                          then body: @escaping (_ current: IndicatorReply, _ preview: IndicatorReply) throws -> Void) {
        listing(completion) { [self] current in
            client.send(IndicatorRequest(.checkPack, pack: file), timeout: packTimeout) { [self] result in
                do {
                    try body(current, try answer(result, to: .checkPack).get())
                } catch {
                    completion(.failure(Self.failure(error)))
                }
            }
        }
    }

    /// - Parameters:
    ///   - preview: The answer to a check.
    ///   - current: The set as it stands.
    /// - Returns: Whether the check found a pack later than the one this Mac has.
    static func isNewer(_ preview: IndicatorReply, than current: IndicatorReply) -> Bool {
        guard let found = preview.pack?.sequence, let has = current.pack?.sequence else { return false }
        return found > has
    }

    /// What to say about an installed pack.
    ///
    /// - Parameters:
    ///   - reply: The Security Extension's answer to the install.
    ///   - source: Where the pack came from, such as “pack.json”, "standard input" or "GitHub".
    /// - Returns: Such as "Installed indicator pack 2 from “pack.json”: 54 indicators now.", and how many of the
    ///   pack's indicators need a newer Mac Monitor, if any.
    static func installed(_ reply: IndicatorReply, from source: String) -> String {
        let release = reply.pack.map { "indicator pack \($0.sequence)" } ?? "the indicator pack"
        let waiting = reply.pack?.needsNewer ?? 0
        let newer = waiting == 0 ? ""
            : " \(waiting) of its indicators \(waiting == 1 ? "needs" : "need") a newer Mac Monitor, and "
                + "\(waiting == 1 ? "isn't" : "aren't") run."
        return "Installed \(release) from \(source): \(count(reply)) now.\(newer)\n"
    }

    /// What to say when GitHub has no newer pack.
    ///
    /// - Parameter reply: The set as it stands.
    /// - Returns: Such as "There's no newer indicator pack. This Mac has pack 2, installed."
    static func newest(_ reply: IndicatorReply) -> String {
        "There's no newer indicator pack. \(has(reply))\n"
    }

    /// - Parameter reply: The set as it stands.
    /// - Returns: Which pack this Mac has, as a sentence.
    static func has(_ reply: IndicatorReply) -> String {
        guard let pack = reply.pack else { return "" }
        switch (pack.source, pack.sequence) {
        case (.installed, let sequence): return "This Mac has pack \(sequence), installed."
        case (.linked, 0): return "This Mac has this build's own indicators."
        case (.linked, let sequence): return "This Mac has pack \(sequence), which this build came with."
        }
    }

    /// What `pack status` says, one fact a line.
    ///
    /// - Parameter pack: The status the Security Extension sent.
    /// - Returns: The text, ending in a newline, every value escaped for a terminal.
    static func status(_ pack: IndicatorPackStatus) -> String {
        let release = pack.source == .installed ? "\(pack.sequence), installed"
            : pack.sequence == 0 ? "this build's own" : "\(pack.sequence), in this build"
        var rows: [(String, String)] = [("Pack", release)]
        if let published = pack.published { rows.append(("Published", published)) }
        if let commit = pack.commit { rows.append(("Commit", String(commit.prefix(7)))) }
        if pack.needsNewer > 0 { rows.append(("Not run", "\(pack.needsNewer) that need a newer Mac Monitor")) }
        if IndicatorPackUpdates.isAvailable {
            rows.append(("Updates", pack.mode?.rawValue ?? "unknown"))
            rows.append(("Last checked", pack.checked ?? "never"))
            rows.append(("Available", pack.available.map { "pack \($0)" } ?? "none"))
        }
        if let problem = pack.problem { rows.append(("Problem", problem)) }
        let width = rows.map(\.0.count).max() ?? 0
        return rows.map { name, value in
            "\(name.padding(toLength: width, withPad: " ", startingAt: 0))   \(TerminalSafeText.text(value))"
        }.joined(separator: "\n") + "\n"
    }

    /// What `pack status --json` writes: every key, with `null` for what there isn't. The update mode, the last look
    /// and the newer pack are left out while pack updates wait (``IndicatorPackUpdates/isAvailable``).
    ///
    /// - Parameter pack: The status the Security Extension sent.
    /// - Returns: The object.
    static func statusObject(_ pack: IndicatorPackStatus) -> [String: Any] {
        let object: [String: Any] = [
            "pack": pack.sequence, "source": pack.source.rawValue, "published": pack.published ?? NSNull(),
            "commit": pack.commit ?? NSNull(), "linked": pack.linked, "needs_newer": pack.needsNewer,
            "problem": pack.problem ?? NSNull()]
        guard IndicatorPackUpdates.isAvailable else { return object }
        let updates: [String: Any] = ["mode": pack.mode?.rawValue ?? NSNull(), "checked": pack.checked ?? NSNull(),
                                      "available": pack.available ?? NSNull()]
        return object.merging(updates) { $1 }
    }

    /// - Parameter object: A JSON object.
    /// - Returns: It, pretty, with its keys sorted, ending in a newline.
    static func json(_ object: [String: Any]) -> Data {
        let options: JSONSerialization.WritingOptions = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return ((try? JSONSerialization.data(withJSONObject: object, options: options)) ?? Data("{}".utf8))
            + Data("\n".utf8)
    }
}
