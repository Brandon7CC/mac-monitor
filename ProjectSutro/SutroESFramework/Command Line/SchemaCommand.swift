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
public enum SchemaCommand {
    /// Write the schema.
    ///
    /// - Parameters:
    ///   - output: Standard output.
    ///   - schema: Reads the schema: the framework's (``TelemetrySchema/data()``), unless a test passes its own.
    /// - Returns: Success, also when the reader closed the pipe (`| head`). Otherwise 70 when the schema can't
    ///   be read, 74 when standard output can't be written.
    public static func run(output: StreamOutput,
                           schema: () throws -> Data = TelemetrySchema.data) -> Result<Void, CommandLineFailure> {
        Result(catching: schema).mapError(CommandLineFailure.schema).flatMap(output.writeResult)
    }
}
