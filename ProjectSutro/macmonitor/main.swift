//
//  main.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import SutroESFramework


/// A closed pipe is an `EPIPE` from `write(2)`, which ends the stream with success, rather than a `SIGPIPE`.
signal(SIGPIPE, SIG_IGN)

CommandLineTool.run(Array(CommandLine.arguments.dropFirst()))

dispatchMain()
