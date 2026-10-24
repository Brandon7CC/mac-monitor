//
//  AtomicESClient.swift
//  AtomicESClient
//
//  Created by Brandon Dalton on 4/19/23.
//
//  BSD 3-Clause License: ../eula.txt
// 
//  Discussion: 
//  AtomicESClient (a very small Endpoint Security (ES) client). AtomicESClient's goal is to provide an easy 
//  to follow example for quickly getting up and going with Apple's Endpoint Security APIs. This code should 
//  only be used as if it were written on a chalkboard -- in other words, purely for example. AtomicESClient 
//  is the very distilled version of an ES client with one event subscription. Much more complete examples
//  exist. Please see the README for a few of those references! 
//
//  Swift compile: `swiftc AtomicESClient.swift -L /Applications/Xcode.app/.../MacOSX.sdk/usr/lib/ -lEndpointSecurity -lbsm -o AtomicESClient`
//  Codesign: `codesign -s $CERT --entitlements atomic_es_ents.plist --force --timestamp --options hard,kill,library-validation AtomicESClient`
//
//  Usage: `sudo ./AtomicESClient`
// 

import Foundation
import EndpointSecurity


// @note: reference: `kern/cs_blobs.h`
// Use a Swift module to expose the Kernel/kern/cs_blobs.h header file
let CS_ADHOC: UInt32 = 0x00000002  /* adhoc signed */

// @discussion: This ES event will give you basic *high level* process execution information.
public var esEventSubs: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_EXEC
]

// MARK: - Process Execution event
// @note: we'll give you a *very* basic model here.
public struct ExampleProcessExecEvent: Identifiable, Codable {
    public var id: UUID = UUID()
    
    public var is_platform_binary, is_adhoc_signed: Bool
    public var process_name, process_path, signing_id, command_line, team_id: String?
    public var pid: Int?
    
    private func parseCommandLine(execEvent: inout es_event_exec_t) -> String {
        let commandLineProducer = (0 ..< Int(es_exec_arg_count(&execEvent))).map {
            String(cString: es_exec_arg(&execEvent, UInt32($0)).data)
        }.joined(separator: " ")

        return commandLineProducer.trimmingCharacters(in: .whitespaces)
    }
    
    init(fromRawEvent rawEvent: UnsafePointer<es_message_t>) {
        var processExecEvent: es_event_exec_t = rawEvent.pointee.event.exec
        
        self.pid = Int(audit_token_to_pid(rawEvent.pointee.process.pointee.audit_token))
        let processURL: NSURL = NSURL(fileURLWithPath:  String(cString: processExecEvent.target.pointee.executable.pointee.path.data))
        self.process_name = processURL.lastPathComponent
        self.process_path = String(cString: processExecEvent.target.pointee.executable.pointee.path.data)
        self.is_platform_binary = processExecEvent.target.pointee.is_platform_binary
        self.is_adhoc_signed = (processExecEvent.target.pointee.codesigning_flags) & CS_ADHOC == CS_ADHOC
        self.command_line = parseCommandLine(execEvent: &processExecEvent)
        
        // @note: basic code signing information
        self.signing_id = String(cString: processExecEvent.target.pointee.signing_id.data)
        
        if processExecEvent.target.pointee.team_id.length > 0 {
            self.team_id = String(cString: processExecEvent.target.pointee.team_id.data)
        }
    }
}

public struct ExampleESEvent: Identifiable, Codable {
    public var id = UUID()
    
    // Top level "ES message" information. Here we're also including the `es_process_t`.
    public var es_event_type, initiating_process_name, initiating_process_path, initiating_process_signing_id: String?
    public var initiating_pid: Int?
    public var mach_time: Int
    
    // Add each event you've modeled here.
    public var exec_event: ExampleProcessExecEvent?
    
    init(fromRawEvent rawEvent: UnsafePointer<es_message_t>) {
        // MARK: - Top-level `es_message_t` / `es_process_t`
        // Reference: https://developer.apple.com/documentation/endpointsecurity/message
        self.mach_time = Int(rawEvent.pointee.mach_time)
        self.initiating_pid = Int(audit_token_to_pid(rawEvent.pointee.process.pointee.parent_audit_token))
        
        let executableURL: NSURL = NSURL(fileURLWithPath:  String(cString: rawEvent.pointee.process.pointee.executable.pointee.path.data))
        self.initiating_process_path = String(cString: rawEvent.pointee.process.pointee.executable.pointee.path.data)
        self.initiating_process_name = executableURL.lastPathComponent ?? "Unknown"
        
        // @note: basic code signing information
        self.initiating_process_signing_id = String(cString: rawEvent.pointee.process.pointee.signing_id.data)
        
        // MARK: - ES event switch
        switch (rawEvent.pointee.event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            self.es_event_type = "ES_EVENT_TYPE_NOTIFY_EXEC"
            self.exec_event = ExampleProcessExecEvent(fromRawEvent: rawEvent)
            break
        default:
            self.es_event_type = "NOT MAPPED"
            break
        }
    }
}

// MARK: - Manage your Endpoint Security (ES) client
public class EndpointSecurityClientManager: NSObject {
    public var esClient: OpaquePointer?
    
    // A simple function to convert an `Encodable` event to JSON.
    public static func eventToJSON(value: Encodable) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        
        let encodedData = try? encoder.encode(value)
        return String(data: encodedData!, encoding: .utf8)!
    }
    
    public func bootupESClient(completion: @escaping (_: String) -> Void) -> OpaquePointer? {
        var client: OpaquePointer?
        
        // MARK: - New ES client
        // Reference: https://developer.apple.com/documentation/endpointsecurity/client
        let result: es_new_client_result_t = es_new_client(&client){ _, event in
            // Here is where the ES client will "send" events to be handled by our app -- this is the "callback".
            completion(EndpointSecurityClientManager.eventToJSON(value: ExampleESEvent(fromRawEvent: event)))
        }
        
        // Check the result of your `es_new_client_result_t` operation. Here is where you'll run into issues like:
        // - Not having the ES entitlement signed to your app.
        // - Not running as `root`, etc.
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            print("[ES CLIENT ERROR] There are too many Endpoint Security clients!")
            break
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            print("[ES CLIENT ERROR] Failed to create new Endpoint Security client! The endpoint security entitlement is required.")
            break
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            print("[ES CLIENT ERROR] Lacking TCC permissions!")
            break
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            print("[ES CLIENT ERROR] Caller is not running as root!")
            break
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            print("[ES CLIENT ERROR] Error communicating with ES!")
            break
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            print("[ES CLIENT ERROR] Incorrect arguments creating a new ES client!")
            break
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            print("[ES CLIENT SUCCESS] We successfully created a new Endpoint Security client!")
            break
        default:
            print("An unknown error occured while creating a new Endpoint Security client!")
        }
        
        // Validate that we have a valid reference to a client
        if client == nil {
            print("[ES CLIENT ERROR] After atempting to make a new ES client we failed.")
            return nil
        }
        
        // MARK: - Event subscriptions
        // Reference: https://developer.apple.com/documentation/endpointsecurity/3228854-es_subscribe
        if es_subscribe(client!, esEventSubs, UInt32(esEventSubs.count)) != ES_RETURN_SUCCESS {
            print("[ES CLIENT ERROR] Failed to subscribe to core events! \(result.rawValue)")
            es_delete_client(client)
            exit(EXIT_FAILURE)
        }
        
        self.esClient = client
        return client
    }
}

// Implement a very simple logger -- here is where your events will be printed.
func logger(jsonEvent: String) {
    print(jsonEvent)
}

func bootupESClientWithLogger() -> OpaquePointer? {
    let esClientManager = EndpointSecurityClientManager()
    let esClient = esClientManager.bootupESClient(completion: logger)
    
    if esClient == nil {
        print("[ES CLIENT ERROR] Error creating the endpoint security client!")
        exit(EXIT_FAILURE)
    }
    
    return esClient
}

func waitForExit() {
    let waitForCTRLC = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    waitForCTRLC.setEventHandler {
        exit(EXIT_SUCCESS)
    }
    
    waitForCTRLC.resume()
    dispatchMain()
}

let esClient = bootupESClientWithLogger()

// Simple `ctrl+c` to exit
waitForExit()
