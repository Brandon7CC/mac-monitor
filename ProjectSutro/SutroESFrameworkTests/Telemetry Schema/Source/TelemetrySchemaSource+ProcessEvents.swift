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
            enrichment("signal_name", .string, "The name of `sig`: SIGKILL."),
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
            enrichment("thread_state_string", .nullable(.string),
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
            enrichment("type", .string, "The name of `fdtype`: PROX_FDTYPE_PIPE."),
            eslogger("pipe", .object(pipe), absent: Absence("the descriptor isn't a pipe")),
        ])
        let certificate = SchemaObject("A signing certificate.", [
            enrichment("summary", .string, "The certificate's subject summary."),
            enrichment("thumbprint", .string, "The certificate's SHA-1 fingerprint, in hex."),
        ])
        return event(ES_EVENT_TYPE_NOTIFY_EXEC, "An exec: es_event_exec_t.", [
            eslogger("target", .ref("process")),
            eslogger("fds", .array(.object(fd))),
            eslogger("script", .nullable(.ref("file"))),
            enrichment("resolved_script_path", .nullable(.string),
                     "The script run: `script`'s path, or, when Endpoint Security reports none, the script an "
                        + "interpreter's arguments name, if the exec's user could read it."),
            enrichment("script_content", .nullable(.string),
                     "The script's text, read when the event was recorded: only if the exec's user could read it and, "
                        + "for `script`, only while it's still the file Endpoint Security reported. It stops at the "
                        + "first NUL byte and at 1 MiB, and invalid UTF-8 reads as U+FFFD."),
            eslogger("cwd", .ref("file")),
            eslogger("last_fd", .integer),
            eslogger("args", .array(.string)),
            eslogger("env", .array(.string)),
            eslogger("image_cputype", .integer),
            eslogger("image_cpusubtype", .integer),
            eslogger("dyld_exec_path", .nullable(.string), "null before message version 7.",
                     absent: Absence("the Mac that wrote the record ran macOS 13.0 to 13.2", observable: false)),
            enrichment("command_line", .string, "`args` joined by spaces."),
            enrichment("executable_age_ms", .nullable(.integer),
                       "Milliseconds from the target's executable's birth (its stat's st_birthtimespec) to the exec. "
                       + "null when the birth time is unknown."),
            enrichment("certificate_chain", .array(.object(certificate)),
                     "The target's signing certificates, leaf first.",
                     absent: Absence("the target has none")),
            enrichment("launched_by_parent", .nullable(.ref("launched_by_parent")),
                     "The process that really caused the target to run; null when it isn't known."),
            enrichment("ancestor_keys", .nullable(.array(.pattern(.processKey))),
                     "The target's ancestors, nearest first, as they were when its process was forked: each one's "
                     + "pid and pid version, as `pid.pidversion`, which name the exec whose target has that audit "
                     + "token. At most 8: the nearest, and the first below launchd, which is never listed. Empty "
                     + "for a child of launchd, and null when the Security Extension wasn't tracking lineage. Since "
                     + "telemetry 1.2.0."),
            yaraScan(of: "the script the exec runs",
                     "An exec carries it while scanning is on, for `script`, for the script an interpreter's "
                     + "arguments name (`resolved_script_path`), and for the Contents/Resources/Scripts/main.scpt of "
                     + "an AppleScript or JXA applet whose executable in Contents/MacOS it runs, whatever its name. "
                     + "It describes that script, not the exec's target. XPScripts.yr applies to a script osascript "
                     + "runs and to an applet's.",
                     absentWhen: "the exec runs no script Mac Monitor found"),
            enrichment("where_froms", .array(.string),
                       "Where the program the exec runs was downloaded from: the strings of the binary property list "
                       + "array in the com.apple.metadata:kMDItemWhereFroms attribute, the download URL and then the "
                       + "page it was found on. They're the first found of the script the exec runs, the bundle the "
                       + "script is the main executable of, the target's executable, and the bundle that is the main "
                       + "executable of. A script is read only if the exec's user could read it. An executable in "
                       + "/System, /bin, /sbin, /usr/bin, "
                       + "/usr/sbin or /usr/libexec isn't read. Read on the Mac that recorded the event, when it "
                       + "recorded it. Since telemetry 1.3.0.",
                       absent: Absence("none of them has the attribute, or the event wasn't recorded by Mac Monitor "
                                       + "3.3.0 or later")),
        ])
    }

    /// A fork: `es_event_fork_t`.
    private static var fork: SchemaEvent {
        event(ES_EVENT_TYPE_NOTIFY_FORK, "A fork: es_event_fork_t.", [
            eslogger("child", .ref("process")),
            enrichment("launched_by_parent", .nullable(.ref("launched_by_parent")),
                     "The process that really caused the child to run; null when it isn't known."),
            enrichment("ancestor_keys", .nullable(.array(.pattern(.processKey))),
                     "The child's ancestors, nearest first, the forking process's first: each one's pid and pid "
                     + "version, as `pid.pidversion`. At most 8: the nearest, and the first below launchd, which "
                     + "is never listed. null when the Security Extension wasn't tracking lineage. Since telemetry "
                     + "1.2.0."),
        ])
    }
}
