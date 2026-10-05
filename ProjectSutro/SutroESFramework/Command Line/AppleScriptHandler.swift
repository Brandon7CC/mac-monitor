//
//  AppleScriptHandler.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - AppleScript handler
/// One handler of a compiled AppleScript, called with text parameters (app context).
///
/// The parameters travel in an Apple event, as descriptors, never as source text, so nothing a parameter holds can
/// change what the script does. `NSAppleScript` belongs on the main thread, and so does every call.
public final class AppleScriptHandler {
    /// Why a call failed: AppleScript's error number (a `do shell script` exit status, or -128 for a cancel) and
    /// message.
    public struct Failure: Error, Equatable {
        /// The error number.
        public let number: Int
        /// The error message.
        public let message: String
    }
    
    /// The compiled script.
    private let script: NSAppleScript
    /// The handler's name.
    private let handler: String
    
    /// Compile a script.
    ///
    /// - Parameters:
    ///   - source: The script's source.
    ///   - handler: The name of the handler ``call(_:)`` calls.
    /// - Returns: `nil` if the script doesn't compile.
    public init?(source: String, handler: String) {
        guard let script = NSAppleScript(source: source) else { return nil }
        var error: NSDictionary?
        guard script.compileAndReturnError(&error) else { return nil }
        self.script = script
        self.handler = handler
    }
    
    /// Call the handler.
    ///
    /// - Parameter parameters: Its parameters, in order.
    /// - Returns: The handler's result as text (`nil` for none), or why it failed.
    public func call(_ parameters: [String]) -> Result<String?, Failure> {
        let list = NSAppleEventDescriptor.list()
        for (index, parameter) in parameters.enumerated() {
            list.insert(NSAppleEventDescriptor(string: parameter), at: index + 1)
        }
        let event = NSAppleEventDescriptor(eventClass: Self.code("ascr"), eventID: Self.code("psbr"),
                                           targetDescriptor: .currentProcess(),
                                           returnID: AEReturnID(kAutoGenerateReturnID),
                                           transactionID: AETransactionID(kAnyTransactionID))
        event.setParam(NSAppleEventDescriptor(string: handler.lowercased()), forKeyword: Self.code("snam"))
        event.setParam(list, forKeyword: keyDirectObject)
        var error: NSDictionary?
        let result = script.executeAppleEvent(event, error: &error)
        guard let error else { return .success(result.stringValue) }
        let number = (error[NSAppleScript.errorNumber] as? NSNumber)?.intValue ?? -1
        return .failure(Failure(number: number, message: error[NSAppleScript.errorMessage] as? String ?? ""))
    }
    
    /// A four character code, such as AppleScript's subroutine event `psbr`.
    ///
    /// - Parameter text: Four ASCII characters.
    /// - Returns: The code.
    static func code(_ text: String) -> FourCharCode {
        text.utf8.reduce(0) { ($0 << 8) | FourCharCode($1) }
    }
}
