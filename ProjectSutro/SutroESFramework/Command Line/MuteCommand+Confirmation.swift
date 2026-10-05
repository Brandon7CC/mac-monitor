//
//  MuteCommand+Confirmation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Asking first
/// `macmonitor mute import` and `mute reset` replace or grow the saved mute set that Mac Monitor and every stream
/// follow, so before they do, they read the set, say what the change would do to it, and ask. A change that would
/// change nothing isn't asked about, unless the Security Extension has a notice about the set (it was written by a
/// newer Mac Monitor, say), which is said first. `--yes` skips the question; without a terminal to ask at, it's
/// required.
extension MuteCommand {
    /// A change asked about first.
    struct PendingChange {
        /// The command, such as "mute reset", for the message when there's no one to ask.
        let command: String
        /// The question, such as "Reset the saved mute set to Mac Monitor's default set?"
        let question: String
        /// What the saved set becomes, from what it is now.
        let result: (MuteList) -> MuteList
        
        /// `mute reset`: the saved set becomes Mac Monitor's default set, which the Security Extension makes for
        /// whoever is logged in at the console. The question names them and their home folder, or says no one is:
        /// over SSH, that may be someone else, or no one.
        ///
        /// - Parameter user: Who's logged in at the console now, if anyone.
        /// - Returns: The change.
        static func reset(for user: ConsoleUser?) -> PendingChange {
            var question = "Reset the saved mute set to Mac Monitor's default set?\n"
            if let user {
                let (name, home) = (TerminalSafeText.text(user.name), TerminalSafeText.text(user.home))
                question += "It mutes the caches and Biome streams of \(home), the home folder of \(name), who's "
                    + "logged in at the console."
            } else {
                question += "No one is logged in at the console, so it leaves out the mutes for a home folder's "
                    + "caches and Biome streams."
            }
            return PendingChange(command: "mute reset", question: question) { _ in .shippedDefault(for: user) }
        }
        
        /// `mute import`: the saved set becomes a file's mutes, or (`--merge`) gains them.
        ///
        /// - Parameters:
        ///   - list: The file's usable mutes.
        ///   - source: Where they came from, such as “mutes.json” or "standard input".
        ///   - merging: Add them to the saved set rather than replace it.
        /// - Returns: The change.
        static func importing(_ list: MuteList, from source: String, merging: Bool) -> PendingChange {
            guard merging else {
                let question = "Replace the saved mute set with the mutes from \(source)?"
                return PendingChange(command: "mute import", question: question) { _ in list }
            }
            let question = "Add the mutes from \(source) to the saved mute set?"
            return PendingChange(command: "mute import", question: question) { current in
                var merged = current
                merged.add(contentsOf: list)
                return merged
            }
        }
    }
    
    /// Waits for answers, off the connection's queue: a person can take a while.
    static let askingQueue = DispatchQueue(label: "com.swiftlydetecting.agent.cli.confirm")
    
    /// Ask about a change, then make it.
    ///
    /// - Parameters:
    ///   - change: The change.
    ///   - send: Makes the change.
    ///   - completion: Called once, on any thread, if the change isn't made: the saved set couldn't be read, the
    ///     answer was no (exit 1), or there was no one to ask (exit 64).
    func ask(about change: PendingChange, then send: @escaping () -> Void,
             otherwise completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        client.send(MuteRequest(.list), timeout: .seconds(10)) { [self] result in
            let reply: MuteReply
            switch result {
            case .success(let answer): reply = answer
            case .failure(let failure): return completion(.failure(failure))
            }
            if let failure = CommandLineFailure.reply(reply) { return completion(.failure(failure)) }
            /// A notice means the set applied isn't the one on disk, so the change matters whatever the numbers say.
            say(reply.notice)
            /// The Security Extension's own entries always read; if they somehow don't, ask without the numbers.
            let effect = (try? MuteFile.list(from: reply.mutes, .saved).list).map { current in
                MuteListChange(from: current, to: change.result(current))
            }
            if effect?.isEmpty == true && reply.notice == nil { return send() }
            let numbers = effect?.isEmpty == false ? effect?.description : nil
            let question = [change.question, numbers, Self.reach].compactMap { $0 }
            Self.askingQueue.async { [self] in
                switch confirm(question.joined(separator: "\n")) {
                case true?: send()
                case false?: completion(.failure(.declined))
                case nil: completion(.failure(.unconfirmed(change.command)))
                }
            }
        }
    }
    
    /// Who a change reaches, and the question.
    static let reach = "Mac Monitor and every stream that follows the saved set apply it right away. Continue?"
}


// MARK: - What a change does
/// What a change does to the saved mute set, mute by mute (a path and its type), for the question `mute import` and
/// `mute reset` ask.
struct MuteListChange: Equatable, CustomStringConvertible {
    /// Mutes for paths and types the set doesn't mute yet.
    let added: Int
    /// Mutes the set loses.
    let removed: Int
    /// Mutes whose events change.
    let changed: Int
    /// How many mutes the set has now.
    let before: Int
    /// How many it has after.
    let after: Int
    
    /// - Parameters:
    ///   - current: The saved set now.
    ///   - next: The saved set after the change.
    init(from current: MuteList, to next: MuteList) {
        let difference = current.difference(to: next)
        added = difference.added.count
        removed = difference.removed.count
        changed = difference.changed.count
        before = current.count
        after = next.count
    }
    
    /// Does the change change nothing?
    var isEmpty: Bool {
        added == 0 && removed == 0 && changed == 0
    }
    
    /// Such as "It adds 1 mute, removes 70 and changes 2: 80 mutes now, 11 after."
    var description: String {
        "It adds \(String.counted(added, "mute")), removes \(removed) and changes \(changed): "
            + "\(String.counted(before, "mute")) now, \(after) after."
    }
}
