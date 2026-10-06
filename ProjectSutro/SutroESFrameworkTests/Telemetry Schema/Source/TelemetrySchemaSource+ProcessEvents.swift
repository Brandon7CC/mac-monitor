//
//  TelemetrySchemaSource+ProcessEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Process events
extension TelemetrySchemaSource {
    /// Process, interprocess and code signing events.
    static var processEvents: [SchemaEvent] {
        [exec, fork,
         event(ES_EVENT_TYPE_NOTIFY_EXIT, "A process's exit: es_event_exit_t.", [eslogger("stat", .integer)]),
         event(ES_EVENT_TYPE_NOTIFY_SIGNAL, "A signal sent: es_event_signal_t.", [
            eslogger("sig", .integer),
            addition("signal_name", .string, "The name of `sig`: SIGKILL."),
            eslogger("target", .ref("process")),
            eslogger("instigator", .nullable(.ref("process")), "null before message version 9."),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
               "A process suspended or resumed: es_event_proc_suspend_resume_t.",
               named("type", "The es_proc_suspend_resume_type_t.") + [eslogger("target", .nullable(.ref("process")))]),
         event(ES_EVENT_TYPE_NOTIFY_PROC_CHECK, "A process inspected: es_event_proc_check_t.",
               named("type", "The es_proc_check_type_t.") + [
            eslogger("flavor", .integer),
            eslogger("target", .nullable(.ref("process"))),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_GET_TASK, "A task port taken: es_event_get_task_t.",
               [eslogger("target", .ref("process"))] + named("type", "The es_get_task_type_t.")),
         event(ES_EVENT_TYPE_NOTIFY_TRACE, "A process traced: es_event_trace_t.", [
            eslogger("target", .ref("process")),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
               "A thread created in another process: es_event_remote_thread_create_t.", [
            eslogger("target", .ref("process")),
            eslogger("thread_state", .nullable(.ref("thread_state"))),
            addition("thread_state_string", .nullable(.string),
                     "The name of the thread state's flavor, for the architecture of the Mac that recorded it."),
         ]),
         event(ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
               "A process's code signature invalidated: es_event_cs_invalidated_t, which has no fields.", []),
        ]
    }
    
    /// An exec: `es_event_exec_t`.
    private static var exec: SchemaEvent {
        let pipe = SchemaObject("A pipe's ID.", [eslogger("pipe_id", .integer)])
        let fd = SchemaObject("An open file descriptor: es_fd_t.", [
            eslogger("fd", .integer),
            eslogger("fdtype", .integer),
            addition("type", .string, "The name of `fdtype`: PROX_FDTYPE_PIPE."),
            eslogger("pipe", .object(pipe), absent: Absence("the descriptor isn't a pipe")),
        ])
        let certificate = SchemaObject("A signing certificate.", [
            addition("summary", .string, "The certificate's subject summary."),
            addition("thumbprint", .string, "The certificate's SHA-1 fingerprint, in hex."),
        ])
        return event(ES_EVENT_TYPE_NOTIFY_EXEC, "An exec: es_event_exec_t.", [
            eslogger("target", .ref("process")),
            eslogger("fds", .array(.object(fd))),
            eslogger("script", .nullable(.ref("file"))),
            addition("resolved_script_path", .nullable(.string),
                     "The script run: `script`'s path, or the script an interpreter's arguments name."),
            addition("script_content", .nullable(.string), "The script's text, read when the event was recorded."),
            eslogger("cwd", .ref("file")),
            eslogger("last_fd", .integer),
            eslogger("args", .array(.string)),
            eslogger("env", .array(.string)),
            eslogger("image_cputype", .integer),
            eslogger("image_cpusubtype", .integer),
            eslogger("dyld_exec_path", .nullable(.string), "null before message version 7.",
                     absent: Absence("the Mac that wrote the record ran macOS 13.0 to 13.2", observable: false)),
            addition("command_line", .string, "`args` joined by spaces."),
            addition("certificate_chain", .array(.object(certificate)),
                     "The target's signing certificates, leaf first.",
                     absent: Absence("the target has none")),
            addition("launched_by_parent", .nullable(.ref("launched_by_parent")),
                     "The process that really caused the target to run; null when it isn't known."),
        ])
    }
    
    /// A fork: `es_event_fork_t`.
    private static var fork: SchemaEvent {
        event(ES_EVENT_TYPE_NOTIFY_FORK, "A fork: es_event_fork_t.", [
            eslogger("child", .ref("process")),
            addition("launched_by_parent", .nullable(.ref("launched_by_parent")),
                     "The process that really caused the child to run; null when it isn't known."),
        ])
    }
}
