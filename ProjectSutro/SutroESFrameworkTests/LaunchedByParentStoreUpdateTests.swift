//
//  LaunchedByParentStoreUpdateTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import CoreData
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Updating a launched-by parent where the event waits
/// Pins how LaunchServices' answer reaches an app's exec after it arrived: in the buffer of events waiting to be
/// stored, or in the store.
final class LaunchedByParentStoreUpdateTests: XCTestCase {
    /// An app's label, as launchd names a LaunchServices instance.
    private let label = XCTestCase.lineageAppLabel
    /// The process that asked LaunchServices to launch the app.
    private let launcher = AuditToken(pid: 700, pidversion: 7000, asid: 100_001, auid: 501, euid: 501, ruid: 501,
                                      rgid: 20, egid: 20)
    
    /// LaunchServices' answer for the app.
    private var launched: LaunchedByParent {
        LaunchedByParent(source: .launchServices, audit_token: launcher,
                         path: "/Applications/Example.app/Contents/MacOS/Example", launchd_job: .init(label: label),
                         resolved_by: .app)
    }
    
    /// The events of an app's launch as the Security Extension stamped them: `xpcproxy`'s exec of the app (pid 4242,
    /// labelled as an app), a fork by it, and its exit.
    ///
    /// - Returns: The exec, the fork and the exit, in that order.
    /// - Throws: The error reading a record, or an `XCTest` failure if the fixture has no process.
    private func appEvents() throws -> [Message] {
        let record = try esloggerExec(parent: (1, 1), env: ["XPC_SERVICE_NAME=\(label)"])
        var exec = try importRecord(try execedByXPCProxy(record))
        exec.resolveLaunchedByParent(by: .securityExtension) { _, _ in nil }
        
        let process = try XCTUnwrap(try fixtureObject("eslogger-exit.jsonl")["process"] as? [String: Any])
        var child = process
        child["audit_token"] = esloggerToken(pid: 4243, pidversion: 4244)
        child["ppid"] = 4242
        child["original_ppid"] = 4242
        child["parent_audit_token"] = process["audit_token"]
        var fork = try importRecord(try esloggerRecord("fork", type: Int(ES_EVENT_TYPE_NOTIFY_FORK.rawValue),
                                                       ["child": child]))
        fork.resolveLaunchedByParent(by: .securityExtension) { _, _ in nil }
        return [exec, fork, try importRecord(try fixtureObject("eslogger-exit.jsonl"))]
    }
    
    /// Another context on the same store, as the view context is one.
    ///
    /// - Parameter context: The context events were stored in.
    /// - Returns: The context, which doesn't merge other contexts' saves.
    private func sibling(of context: NSManagedObjectContext) -> NSManagedObjectContext {
        let sibling = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
        sibling.persistentStoreCoordinator = context.persistentStoreCoordinator
        return sibling
    }
    
    /// An exec loaded in a context, with its launched-by parent read, as a table row or Event Facts loads one. The
    /// context keeps its copy while it's held.
    ///
    /// - Parameters:
    ///   - id: The event's `id`.
    ///   - context: The context.
    /// - Returns: The exec, or `nil` when the store doesn't have it.
    /// - Throws: The fetch's error.
    private func exec(of id: UUID, in context: NSManagedObjectContext) throws -> ESProcessExecEvent? {
        try context.performAndWait {
            let request = ESMessage.fetchRequest()
            request.predicate = NSPredicate(format: "id == %@", id as CVarArg)
            let exec = try context.fetch(request).first?.event.exec
            _ = exec?.launched_by_parent
            return exec
        }
    }
    
    /// An event's launched-by parent as the store has it, read through a context of its own.
    ///
    /// - Parameters:
    ///   - id: The event's `id`.
    ///   - context: A context on the store.
    /// - Returns: The launched-by parent, or `nil`.
    /// - Throws: The fetch's error.
    private func savedLaunchedByParent(of id: UUID,
                                       alongside context: NSManagedObjectContext) throws -> LaunchedByParent? {
        let reader = sibling(of: context)
        return try reader.performAndWait { try exec(of: id, in: reader)?.launched_by_parent }
    }
    
    /// A stored exec takes the answer, and the store keeps it once saved.
    ///
    /// - Throws: The error storing or reading the events, or an `XCTest` failure if the exec isn't updated.
    func testStoredExecIsUpdated() throws {
        let events = try appEvents()
        XCTAssertEqual(events[0].createdLaunchedByParent?.source, .launchdJob)
        try withEventStore(events) { context, stored in
            let exec = stored[0], id = stored[0].id
            XCTAssertEqual(exec.createdLaunchedByParent?.source, .launchdJob)
            let updated = try XCTUnwrap(ESMessage.applyLaunchedByParent(launched, toEventWithID: id, in: context))
            XCTAssertEqual(updated.objectID, exec.objectID)
            XCTAssertEqual(exec.createdLaunchedByParent, launched)
            try context.save()
            XCTAssertEqual(try savedLaunchedByParent(of: id, alongside: context), launched)
        }
    }
    
    /// An update is saved at once, and a view context that already has the exec shows it, though it doesn't merge
    /// saves. Another context keeps its copy, and one without the exec isn't given it.
    ///
    /// - Throws: The error storing or reading the events, or an `XCTest` failure if a context lacks the exec.
    func testUpdateIsSavedAndShown() throws {
        try withEventStore(try appEvents()) { context, stored in
            let id = stored[0].id
            let view = sibling(of: context), other = sibling(of: context), empty = sibling(of: context)
            let shown = try XCTUnwrap(try exec(of: id, in: view)), kept = try XCTUnwrap(try exec(of: id, in: other))
            let update = LaunchedByParentStoreUpdate(context: context, viewContext: view)
            XCTAssertEqual(update.apply(launched, toEventWithID: id, canSave: true, hasUnsavedEvents: false), .saved)
            XCTAssertFalse(context.hasChanges)
            XCTAssertEqual(try savedLaunchedByParent(of: id, alongside: context), launched)
            XCTAssertEqual(view.performAndWait { shown.launched_by_parent }, launched)
            XCTAssertEqual(other.performAndWait { kept.launched_by_parent?.source }, .launchdJob, "it merges nothing")
            XCTAssertEqual(try exec(of: id, in: other)?.launched_by_parent?.source, .launchdJob, "nor does a fetch")
            
            let quiet = LaunchedByParentStoreUpdate(context: context, viewContext: empty)
            XCTAssertEqual(quiet.apply(launched, toEventWithID: id, canSave: true, hasUnsavedEvents: false), .saved)
            let execID = try XCTUnwrap(stored[0].event.exec?.objectID)
            XCTAssertNil(empty.performAndWait { empty.registeredObject(for: execID) })
        }
    }
    
    /// While a failed save has left events unsaved, the update waits for the next insert's save.
    ///
    /// - Throws: The error storing, saving or reading the events.
    func testUpdateRidesAlongWithTheNextInsert() throws {
        try withEventStore(try appEvents()) { context, stored in
            let id = stored[0].id
            let update = LaunchedByParentStoreUpdate(context: context, viewContext: nil)
            XCTAssertEqual(update.apply(launched, toEventWithID: id, canSave: true, hasUnsavedEvents: true), .deferred)
            XCTAssertTrue(context.hasChanges)
            XCTAssertEqual(try savedLaunchedByParent(of: id, alongside: context)?.source, .launchdJob)
            /// The next insert's save.
            try context.save()
            XCTAssertEqual(try savedLaunchedByParent(of: id, alongside: context), launched)
        }
    }
    
    /// Without a store, or while Mac Monitor quits, nothing changes; nor for an `id` the store doesn't have.
    ///
    /// - Throws: The error storing the events.
    func testNothingWithoutAStoreOrAnExec() throws {
        try withEventStore(try appEvents()) { context, stored in
            let update = LaunchedByParentStoreUpdate(context: context, viewContext: nil)
            XCTAssertEqual(update.apply(launched, toEventWithID: stored[0].id, canSave: false, hasUnsavedEvents: false),
                           .notSaving)
            XCTAssertEqual(update.apply(launched, toEventWithID: UUID(), canSave: true, hasUnsavedEvents: false),
                           .notFound)
            XCTAssertFalse(context.hasChanges)
            XCTAssertEqual(stored[0].createdLaunchedByParent?.source, .launchdJob)
        }
    }
    
    /// An update whose save fails (here, because another context changed the exec first) is rolled back, and the
    /// store keeps the earlier answer.
    ///
    /// - Throws: The error storing, saving or reading the events.
    func testFailedSaveIsRolledBack() throws {
        try withEventStore(try appEvents()) { context, stored in
            let id = stored[0].id
            XCTAssertEqual(stored[0].createdLaunchedByParent?.source, .launchdJob)
            let earlier = LaunchedByParent(source: .launchServices, audit_token: nil, pid: nil, path: nil,
                                           launchd_job: .init(label: label), resolved_by: .app)
            let writer = sibling(of: context)
            try writer.performAndWait {
                XCTAssertNotNil(ESMessage.applyLaunchedByParent(earlier, toEventWithID: id, in: writer))
                try writer.save()
            }
            let update = LaunchedByParentStoreUpdate(context: context, viewContext: nil)
            XCTAssertEqual(update.apply(launched, toEventWithID: id, canSave: true, hasUnsavedEvents: false),
                           .rolledBack)
            XCTAssertFalse(context.hasChanges)
            XCTAssertEqual(try savedLaunchedByParent(of: id, alongside: context), earlier)
        }
    }
    
    /// An `id` the store doesn't have changes nothing.
    ///
    /// - Throws: The error storing the events.
    func testUnknownEventIsNotFound() throws {
        try withEventStore(try appEvents()) { context, _ in
            XCTAssertNil(ESMessage.applyLaunchedByParent(launched, toEventWithID: UUID(), in: context))
            XCTAssertFalse(context.hasChanges)
        }
    }
    
    /// Only an exec takes the answer: a fork or any other event with that `id` is left alone.
    ///
    /// - Throws: The error storing the events.
    func testOnlyExecsAreUpdated() throws {
        try withEventStore(try appEvents()) { context, stored in
            let fork = stored[1], exit = stored[2]
            XCTAssertNil(ESMessage.applyLaunchedByParent(launched, toEventWithID: fork.id, in: context))
            XCTAssertNil(ESMessage.applyLaunchedByParent(launched, toEventWithID: exit.id, in: context))
            XCTAssertFalse(context.hasChanges)
            XCTAssertEqual(fork.createdLaunchedByParent?.source, .unixParent)
            XCTAssertNil(exit.createdLaunchedByParent)
        }
    }
    
    /// An event still waiting in the buffer is found by its `id` and patched in place; the others are left alone.
    ///
    /// - Throws: The error reading the events.
    func testBufferedEventIsPatched() throws {
        var buffer = try appEvents()
        let fork = buffer[1].createdLaunchedByParent
        XCTAssertTrue(buffer.setLaunchedByParent(launched, ofEventWithID: buffer[0].id))
        XCTAssertEqual(buffer[0].createdLaunchedByParent, launched)
        XCTAssertEqual(buffer[1].createdLaunchedByParent, fork)
        XCTAssertNil(buffer[2].createdLaunchedByParent)
        XCTAssertFalse(buffer.setLaunchedByParent(launched, ofEventWithID: UUID()))
    }
}
