//
//  SchemaCommand.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Schema command
/// `macmonitor schema` (command line context): write the telemetry schema the framework bundles to standard output,
/// byte for byte as `Schema/mac-monitor-telemetry.schema.json` is committed, so `macmonitor schema > file` saves the
/// file a release attaches. Needs neither root nor the Security Extension.
public struct SchemaCommand {
    private let output: StreamOutput
    /// Reads the schema.
    private let schema: () throws -> Data
    
    /// - Parameters:
    ///   - output: Standard output.
    ///   - schema: Reads the schema: the framework's (``TelemetrySchema/data()``), unless a test passes its own.
    public init(output: StreamOutput, schema: @escaping () throws -> Data = TelemetrySchema.data) {
        self.output = output
        self.schema = schema
    }
    
    /// Write the schema.
    ///
    /// - Returns: Success, also when the reader closed the pipe (`| head`); or the failure: 70 when the schema can't
    ///   be read, 74 when standard output can't be written.
    public func run() -> Result<Void, CommandLineFailure> {
        let data: Data
        do {
            data = try schema()
        } catch {
            return .failure(.schema(error))
        }
        return output.writeResult(data)
    }
}
