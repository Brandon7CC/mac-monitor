//
//  ConstantNamesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Names of constants
/// Pins the name Mac Monitor gives each value of an Endpoint Security enum or a family of Darwin constants
/// (``ConstantNames``), which exports and the wire's JSON carry: each value from −1 to 300, and each named value
/// beyond, against a frozen copy of the names their `switch`es gave before they became tables.
final class ConstantNamesTests: XCTestCase {
    /// Every Open Directory error code's name and meaning, after the code.
    private static let odErrors = """
        0 `kODErrorSuccess`: The operation was successful.
        1000 `kODErrorSessionLocalOnlyDaemonInUse`: A Local Only session was initiated and is still active.
        1001 `kODErrorSessionNormalDaemonInUse`: The Normal daemon is still in use but request was issued for Local \
        only.
        1002 `kODErrorSessionDaemonNotRunning`: The daemon is not running.
        1003 `kODErrorSessionDaemonRefused`: The daemon refused the session.
        1100 `kODErrorSessionProxyCommunicationError`: There was a communication error with the remote daemon.
        1101 `kODErrorSessionProxyVersionMismatch`: Versions mismatch between the remote daemon and local framework.
        1102 `kODErrorSessionProxyIPUnreachable`: The provided kODSessionProxyAddress did not respond.
        1103 `kODErrorSessionProxyUnknownHost`: The provided kODSessionProxyAddress cannot be resolved.
        2000 `kODErrorNodeUnknownName`: The node name provided does not exist and cannot be opened.
        2001 `kODErrorNodeUnknownType`: The node type provided is not a known value.
        2100 `kODErrorNodeConnectionFailed`: A node connection failed.
        2200 `kODErrorNodeUnknownHost`: An invalid host is provided.
        3000 `kODErrorQuerySynchronize`: A synchronize has been initiated.
        3100 `kODErrorQueryInvalidMatchType`: An invalid match type is provided in a query.
        3101 `kODErrorQueryUnsupportedMatchType`: The plugin does not support the requested match type.
        3102 `kODErrorQueryTimeout`: The query timed out during the request.
        4000 `kODErrorRecordReadOnlyNode`: The record cannot be modified.
        4001 `kODErrorRecordPermissionError`: The changes requested were denied due to insufficient permissions.
        4100 `kODErrorRecordParameterError`: An invalid parameter was provided.
        4101 `kODErrorRecordInvalidType`: An invalid record type was provided.
        4102 `kODErrorRecordAlreadyExists`: The record create failed because the record already exists.
        4103 `kODErrorRecordTypeDisabled`: The particular record type is disabled by policy for a plugin.
        4200 `kODErrorRecordAttributeUnknownType`: An unknown attribute type is provided.
        4201 `kODErrorRecordAttributeNotFound`: The requested attribute is not found in the record.
        4202 `kODErrorRecordAttributeValueSchemaError`: An attribute value does not meet schema requirements.
        4203 `kODErrorRecordAttributeValueNotFound`: An attribute value is not found in a record.
        5000 `kODErrorCredentialsInvalid`: The provided credentials are invalid with the current node.
        5100 `kODErrorCredentialsMethodNotSupported`: A particular extended method is not supported by the node.
        5101 `kODErrorCredentialsNotAuthorized`: An operation such as changing a password is not authorized with \
        current privileges.
        5102 `kODErrorCredentialsParameterError`: A parameter provided is invalid.
        5103 `kODErrorCredentialsOperationFailed`: The requested operation failed (usually due to some unrecoverable \
        error).
        5200 `kODErrorCredentialsServerUnreachable`: The authentication server is not reachable.
        5201 `kODErrorCredentialsServerNotFound`: The authentication server could not be found for the requested \
        operation.
        5202 `kODErrorCredentialsServerError`: The authentication server encountered an error.
        5203 `kODErrorCredentialsServerTimeout`: The authentication server timed out.
        5204 `kODErrorCredentialsContactPrimary`: The authentication server is not the primary and the operation \
        requires the primary.
        5205 `kODErrorCredentialsServerCommunicationError`: The authentication server had a communication error.
        5300 `kODErrorCredentialsAccountNotFound`: The authentication server could not find the provided account.
        5301 `kODErrorCredentialsAccountDisabled`: The account is disabled.
        5302 `kODErrorCredentialsAccountExpired`: The account has expired.
        5303 `kODErrorCredentialsAccountInactive`: The account is inactive.
        5304 `kODErrorCredentialsAccountTemporarilyLocked`: The account is in backoff (verification attempts ignored \
        for a period of time).
        5305 `kODErrorCredentialsAccountLocked`: The account is locked due to too many verification failures.
        5400 `kODErrorCredentialsPasswordExpired`: The password has expired and must be changed.
        5401 `kODErrorCredentialsPasswordChangeRequired`: A password change is required.
        5402 `kODErrorCredentialsPasswordQualityFailed`: The password provided for change did not meet quality \
        minimum requirements.
        5403 `kODErrorCredentialsPasswordTooShort`: The provided password is too short.
        5404 `kODErrorCredentialsPasswordTooLong`: The provided password is too long.
        5405 `kODErrorCredentialsPasswordNeedsLetter`: The password needs a letter.
        5406 `kODErrorCredentialsPasswordNeedsDigit`: The password needs a digit.
        5407 `kODErrorCredentialsPasswordChangeTooSoon`: An attempt to change a password is made too soon before the \
        last change.
        5408 `kODErrorCredentialsPasswordUnrecoverable`: The password was not recoverable from the authentication \
        database.
        5500 `kODErrorCredentialsInvalidLogonHours`: An account attempts to log in outside of set logon hours.
        5501 `kODErrorCredentialsInvalidComputer`: An account attempts to log in to a computer they are not authorized.
        6000 `kODErrorPolicyUnsupported`: All requested policies were not supported.
        6001 `kODErrorPolicyOutOfRange`: The policy value was beyond the allowed range.
        10000 `kODErrorPluginOperationNotSupported`: The plugin does not support the requested operation.
        10001 `kODErrorPluginError`: The plugin has encountered some undefined error.
        10002 `kODErrorDaemonError`: Some error occurred inside the daemon.
        10003 `kODErrorPluginOperationTimeout`: An operation exceeds an imposed timeout.
        """
    
    /// Checks the name of each value from −1 to 300 and each value `frozen` names.
    ///
    /// - Parameters:
    ///   - prefix: The prefix of every name in `frozen`.
    ///   - frozen: The names, without `prefix`, by value.
    ///   - values: The values to check besides those `frozen` names.
    ///   - unknown: The name of a value `frozen` doesn't name.
    ///   - name: The name the code under test gives a value.
    private func assertNames(_ prefix: String, _ frozen: [Int: String], values: ClosedRange<Int> = -1...300,
                             unknown: (Int) -> String, file: StaticString = #filePath, line: UInt = #line,
                             _ name: (Int) -> String) {
        for value in Set(values).union(frozen.keys).sorted() {
            XCTAssertEqual(name(value), frozen[value].map { prefix + $0 } ?? unknown(value), "value \(value)",
                           file: file, line: line)
        }
    }
    
    /// Checks the name an enriched model gives each value from −1 to 300 of one of its fields, and each value
    /// `frozen` names.
    ///
    /// - Parameters:
    ///   - field: The field.
    ///   - name: The field's name, which ``ESEnrichable/enrich()`` derives.
    ///   - prefix: The prefix of every name in `frozen`.
    ///   - frozen: The names, without `prefix`, by value.
    ///   - unknown: The name of a value `frozen` doesn't name.
    /// - Throws: The error decoding an empty model.
    private func assertEnriched<Model: ESEnrichable & Decodable, Value: BinaryInteger>(
        _ field: WritableKeyPath<Model, Value>, _ name: KeyPath<Model, String>, _ prefix: String,
        _ frozen: [Int: String], unknown: String = "UNKNOWN", file: StaticString = #filePath, line: UInt = #line
    ) throws {
        var model = try TraceDecoder(NSDictionary()).decode(Model.self)
        assertNames(prefix, frozen, unknown: { _ in unknown }, file: file, line: line) {
            model[keyPath: field] = Value(truncatingIfNeeded: $0)
            model.enrich()
            return model[keyPath: name]
        }
    }
    
    /// A `tcc_modify` event's identity type, update type, right and reason, "Unknown" for another value.
    func testTCCModify() throws {
        try assertEnriched(\TCCModifyEvent.identity_type, \.identity_type_string, "ES_TCC_IDENTITY_TYPE_", [
            0: "BUNDLE_ID", 1: "EXECUTABLE_PATH", 2: "POLICY_ID", 3: "FILE_PROVIDER_DOMAIN_ID",
        ], unknown: "Unknown")
        try assertEnriched(\TCCModifyEvent.update_type, \.update_type_string, "ES_TCC_EVENT_TYPE_", [
            0: "UNKNOWN", 1: "CREATE", 2: "MODIFY", 3: "DELETE",
        ], unknown: "Unknown")
        try assertEnriched(\TCCModifyEvent.right, \.right_string, "ES_TCC_AUTHORIZATION_RIGHT_", [
            0: "DENIED", 1: "UNKNOWN", 2: "ALLOWED", 3: "LIMITED", 4: "ADD_MODIFY_ADDED", 5: "SESSION_PID",
            6: "LEARN_MORE",
        ], unknown: "Unknown")
        try assertEnriched(\TCCModifyEvent.reason, \.reason_string, "ES_TCC_AUTHORIZATION_REASON_", [
            0: "NONE", 1: "ERROR", 2: "USER_CONSENT", 3: "USER_SET", 4: "SYSTEM_SET", 5: "SERVICE_POLICY",
            6: "MDM_POLICY", 7: "SERVICE_OVERRIDE_POLICY", 8: "MISSING_USAGE_STRING", 9: "PROMPT_TIMEOUT",
            10: "PREFLIGHT_UNKNOWN", 11: "ENTITLED", 12: "APP_TYPE_POLICY", 13: "PROMPT_CANCEL",
        ], unknown: "Unknown")
    }
    
    /// A `proc_check` event's type.
    func testProcessCheck() throws {
        try assertEnriched(\ProcessCheckEvent.type, \.type_string, "ES_PROC_CHECK_TYPE_", [
            1: "LISTPIDS", 2: "PIDINFO", 3: "PIDFDINFO", 4: "KERNMSGBUF", 5: "SETCONTROL", 6: "PIDFILEPORTINFO",
            7: "TERMINATE", 8: "DIRTYCONTROL", 9: "PIDRUSAGE", 14: "UDATA_INFO",
        ])
    }
    
    /// An `xpc_connect` event's service domain type, named without `ES_XPC_DOMAIN_TYPE_`.
    func testXPCConnect() throws {
        try assertEnriched(\XPCConnectEvent.service_domain_type, \.service_domain_type_string, "", [
            1: "SYSTEM", 2: "USER", 3: "USER LOGIN", 4: "SESSION", 5: "PID", 6: "MANAGER", 7: "PORT", 8: "GUI",
        ])
    }
    
    /// A `mount` event's disposition.
    func testMount() throws {
        try assertEnriched(\MountEvent.disposition, \.disposition_string, "ES_MOUNT_DISPOSITION_", [
            0: "EXTERNAL", 1: "INTERNAL", 2: "NETWORK", 3: "VIRTUAL", 4: "NULLFS", 5: "UNKNOWN",
        ])
    }
    
    /// A `proc_suspend_resume` event's type.
    func testProcessSuspendResume() throws {
        try assertEnriched(\ProcessSocketEvent.type, \.type_string, "ES_PROC_SUSPEND_RESUME_TYPE_", [
            0: "SUSPEND", 1: "RESUME", 3: "SHUTDOWN_SOCKETS",
        ])
    }
    
    /// A `get_task` event's type.
    func testGetTask() throws {
        try assertEnriched(\GetTaskEvent.type, \.type_string, "ES_GET_TASK_TYPE_", [
            0: "TASK_FOR_PID", 1: "EXPOSE_TASK", 2: "IDENTITY_TOKEN",
        ])
    }
    
    /// An `authorization_judgement` result's rule class, from 0: Endpoint Security's is unsigned.
    func testAuthorizationJudgement() {
        assertNames("ES_AUTHORIZATION_RULE_CLASS_", [
            0: "USER", 1: "RULE", 2: "MECHANISM", 3: "ALLOW", 4: "DENY", 5: "UNKNOWN", 6: "INVALID",
        ], values: 0...300, unknown: { _ in "UNKNOWN" }) {
            let rule = es_authorization_rule_class_t(rawValue: UInt32($0))
            let result = es_authorization_result_t(right_name: es_string_token_t(), rule_class: rule, granted: false)
            return ESAuthorizationResult(from: result).rule_class_string
        }
    }
    
    /// An `openssh_login` event's result type and source address type, and an `openssh_logout` event's source
    /// address type, "Unknown" for another value.
    func testOpenSSH() throws {
        try assertEnriched(\SSHLoginEvent.result_type, \.result_type_string, "ES_OPENSSH_", [
            0: "LOGIN_EXCEED_MAXTRIES", 1: "LOGIN_ROOT_DENIED", 2: "AUTH_SUCCESS", 3: "AUTH_FAIL_NONE",
            4: "AUTH_FAIL_PASSWD", 5: "AUTH_FAIL_KBDINT", 6: "AUTH_FAIL_PUBKEY", 7: "AUTH_FAIL_HOSTBASED",
            8: "AUTH_FAIL_GSSAPI", 9: "INVALID_USER",
        ])
        let addressTypes = [
            0: "NONE", 1: "IPV4", 2: "IPV6", 3: "NAMED_SOCKET",
        ]
        try assertEnriched(\SSHLoginEvent.source_address_type, \.source_address_type_string, "ES_ADDRESS_TYPE_",
                           addressTypes)
        try assertEnriched(\SSHLogoutEvent.source_address_type, \.source_address_type_string, "ES_ADDRESS_TYPE_",
                           addressTypes, unknown: "Unknown")
    }
    
    /// A `signal` event's signal, "IS-ALIVE" for 0.
    func testSignal() throws {
        try assertEnriched(\ProcessSignalEvent.sig, \.signal_name, "", [
            0: "IS-ALIVE", 1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGEMT",
            8: "SIGFPE", 9: "SIGKILL", 10: "SIGBUS", 11: "SIGSEGV", 12: "SIGSYS", 13: "SIGPIPE", 14: "SIGALRM",
            15: "SIGTERM", 16: "SIGURG", 17: "SIGSTOP", 18: "SIGTSTP", 19: "SIGCONT", 20: "SIGCHLD", 21: "SIGTTIN",
            22: "SIGTTOU", 23: "SIGIO", 24: "SIGXCPU", 25: "SIGXFSZ", 26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH",
            29: "SIGINFO", 30: "SIGUSR1", 31: "SIGUSR2",
        ])
    }
    
    /// A muted path's type, `ES_MUTE_PATH_TYPE_TARGET_PREFIX` for another value.
    func testMutePathType() {
        assertNames("ES_MUTE_PATH_TYPE_", [
            0: "PREFIX", 1: "LITERAL", 2: "TARGET_PREFIX", 3: "TARGET_LITERAL",
        ], unknown: { _ in "ES_MUTE_PATH_TYPE_TARGET_PREFIX" }) {
            getMuteCaseString(muteType: es_mute_path_type_t(rawValue: UInt32(truncatingIfNeeded: $0)))
        }
    }
    
    /// A file descriptor's type.
    func testFileDescriptor() throws {
        try assertEnriched(\FileDescriptor.fdtype, \.type, "PROX_FDTYPE_", [
            0: "ATALK", 1: "VNODE", 2: "SOCKET", 3: "PSHM", 4: "PSEM", 5: "KQUEUE", 6: "PIPE", 7: "FSEVENTS",
            9: "NETPOLICY", 10: "CHANNEL", 11: "NEXUS",
        ])
    }
    
    /// A launch item's type.
    func testLaunchItem() throws {
        try assertEnriched(\LaunchItem.item_type, \.item_type_string, "ES_BTM_ITEM_TYPE_", [
            0: "USER_ITEM", 1: "APP", 2: "LOGIN_ITEM", 3: "AGENT", 4: "DAEMON",
        ])
    }
    
    /// An Open Directory error code's name and meaning, "Unknown" for another code.
    func testOpenDirectoryErrors() {
        let frozen = Dictionary(uniqueKeysWithValues: Self.odErrors.split(separator: "\n").map { line in
            let parts = line.split(separator: " ", maxSplits: 1)
            return (Int(parts[0]) ?? -1, String(parts[1]))
        })
        XCTAssertEqual(frozen.count, 61)
        assertNames("", frozen, unknown: { _ in "Unknown" }) { decodeODErrorCode($0) }
    }
    
    /// A socket's type, "UNKNOWN" for another, and its domain and protocol, "UNKNOWN(n)" for another. Of two names for
    /// one value the first in `<sys/socket.h>` or `<netinet/in.h>` wins, and protocol 0 is "DEFAULT".
    func testSocket() {
        assertNames("SOCK_", [
            1: "STREAM", 2: "DGRAM", 3: "RAW", 4: "RDM", 5: "SEQPACKET",
        ], unknown: { _ in "UNKNOWN" }) { resolve(type: Int32($0)) }
        assertNames("", [
            0: "AF_UNSPEC", 1: "AF_UNIX", 2: "AF_INET", 3: "AF_IMPLINK", 4: "AF_PUP", 5: "AF_CHAOS", 6: "AF_NS",
            7: "AF_ISO", 8: "AF_ECMA", 9: "AF_DATAKIT", 10: "AF_CCITT", 11: "AF_SNA", 12: "AF_DECnet", 13: "AF_DLI",
            14: "AF_LAT", 15: "AF_HYLINK", 16: "AF_APPLETALK", 17: "AF_ROUTE", 18: "AF_LINK", 19: "pseudo_AF_XTP",
            20: "AF_COIP", 21: "AF_CNT", 22: "pseudo_AF_RTIP", 23: "AF_IPX", 24: "AF_SIP", 25: "pseudo_AF_PIP",
            27: "AF_NDRV", 28: "AF_ISDN", 29: "pseudo_AF_KEY", 30: "AF_INET6", 31: "AF_NATM", 32: "AF_SYSTEM",
            33: "AF_NETBIOS", 34: "AF_PPP", 35: "pseudo_AF_HDRCMPLT", 36: "AF_RESERVED_36", 37: "AF_IEEE80211",
            38: "AF_UTUN", 40: "AF_VSOCK",
        ], unknown: { "UNKNOWN(\($0))" }) { resolve(domain: Int32($0)) }
        assertNames("", [
            0: "DEFAULT", 1: "IPPROTO_ICMP", 2: "IPPROTO_IGMP", 3: "IPPROTO_GGP", 4: "IPPROTO_IPV4", 6: "IPPROTO_TCP",
            7: "IPPROTO_ST", 8: "IPPROTO_EGP", 9: "IPPROTO_PIGP", 10: "IPPROTO_RCCMON", 11: "IPPROTO_NVPII",
            12: "IPPROTO_PUP", 13: "IPPROTO_ARGUS", 14: "IPPROTO_EMCON", 15: "IPPROTO_XNET", 16: "IPPROTO_CHAOS",
            17: "IPPROTO_UDP", 18: "IPPROTO_MUX", 19: "IPPROTO_MEAS", 20: "IPPROTO_HMP", 21: "IPPROTO_PRM",
            22: "IPPROTO_IDP", 23: "IPPROTO_TRUNK1", 24: "IPPROTO_TRUNK2", 25: "IPPROTO_LEAF1", 26: "IPPROTO_LEAF2",
            27: "IPPROTO_RDP", 28: "IPPROTO_IRTP", 29: "IPPROTO_TP", 30: "IPPROTO_BLT", 31: "IPPROTO_NSP",
            32: "IPPROTO_INP", 33: "IPPROTO_SEP", 34: "IPPROTO_3PC", 35: "IPPROTO_IDPR", 36: "IPPROTO_XTP",
            37: "IPPROTO_DDP", 38: "IPPROTO_CMTP", 39: "IPPROTO_TPXX", 40: "IPPROTO_IL", 41: "IPPROTO_IPV6",
            42: "IPPROTO_SDRP", 43: "IPPROTO_ROUTING", 44: "IPPROTO_FRAGMENT", 45: "IPPROTO_IDRP", 46: "IPPROTO_RSVP",
            47: "IPPROTO_GRE", 48: "IPPROTO_MHRP", 49: "IPPROTO_BHA", 50: "IPPROTO_ESP", 51: "IPPROTO_AH",
            52: "IPPROTO_INLSP", 53: "IPPROTO_SWIPE", 54: "IPPROTO_NHRP", 58: "IPPROTO_ICMPV6", 59: "IPPROTO_NONE",
            60: "IPPROTO_DSTOPTS", 61: "IPPROTO_AHIP", 62: "IPPROTO_CFTP", 63: "IPPROTO_HELLO", 64: "IPPROTO_SATEXPAK",
            65: "IPPROTO_KRYPTOLAN", 66: "IPPROTO_RVD", 67: "IPPROTO_IPPC", 68: "IPPROTO_ADFS", 69: "IPPROTO_SATMON",
            70: "IPPROTO_VISA", 71: "IPPROTO_IPCV", 72: "IPPROTO_CPNX", 73: "IPPROTO_CPHB", 74: "IPPROTO_WSN",
            75: "IPPROTO_PVP", 76: "IPPROTO_BRSATMON", 77: "IPPROTO_ND", 78: "IPPROTO_WBMON", 79: "IPPROTO_WBEXPAK",
            80: "IPPROTO_EON", 81: "IPPROTO_VMTP", 82: "IPPROTO_SVMTP", 83: "IPPROTO_VINES", 84: "IPPROTO_TTP",
            85: "IPPROTO_IGP", 86: "IPPROTO_DGP", 87: "IPPROTO_TCF", 88: "IPPROTO_IGRP", 89: "IPPROTO_OSPFIGP",
            90: "IPPROTO_SRPC", 91: "IPPROTO_LARP", 92: "IPPROTO_MTP", 93: "IPPROTO_AX25", 94: "IPPROTO_IPEIP",
            95: "IPPROTO_MICP", 96: "IPPROTO_SCCSP", 97: "IPPROTO_ETHERIP", 98: "IPPROTO_ENCAP", 99: "IPPROTO_APES",
            100: "IPPROTO_GMTP", 103: "IPPROTO_PIM", 108: "IPPROTO_IPCOMP", 113: "IPPROTO_PGM", 132: "IPPROTO_SCTP",
            254: "IPPROTO_DIVERT", 255: "IPPROTO_RAW", 257: "IPPROTO_DONE",
        ], unknown: { "UNKNOWN(\($0))" }) { resolve(protocol: Int32($0)) }
    }
}
