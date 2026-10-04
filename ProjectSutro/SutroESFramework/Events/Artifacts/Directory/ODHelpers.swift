//
//  ODHelpers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/29/23.
//

import Foundation
//import SwiftODConstants


/// The name and meaning of an Open Directory error code, from `odconstants.h`.
///
/// - Parameter errorCode: An Open Directory event's `error_code`.
/// - Returns: The error's name and description, or `Unknown` for a code `odconstants.h` doesn't define.
public func decodeODErrorCode(_ errorCode: Int) -> String {
    guard let code = UInt32(exactly: errorCode) else { return "Unknown" }
    switch ODFrameworkErrors(code) {
    case kODErrorSuccess:
        return "`kODErrorSuccess`: The operation was successful."
    case kODErrorSessionLocalOnlyDaemonInUse:
        return "`kODErrorSessionLocalOnlyDaemonInUse`: A Local Only session was initiated and is still active."
    case kODErrorSessionNormalDaemonInUse:
        return "`kODErrorSessionNormalDaemonInUse`: The Normal daemon is still in use but request was issued for Local only."
    case kODErrorSessionDaemonNotRunning:
        return "`kODErrorSessionDaemonNotRunning`: The daemon is not running."
    case kODErrorSessionDaemonRefused:
        return "`kODErrorSessionDaemonRefused`: The daemon refused the session."
    case kODErrorSessionProxyCommunicationError:
        return "`kODErrorSessionProxyCommunicationError`: There was a communication error with the remote daemon."
    case kODErrorSessionProxyVersionMismatch:
        return "`kODErrorSessionProxyVersionMismatch`: Versions mismatch between the remote daemon and local framework."
    case kODErrorSessionProxyIPUnreachable:
        return "`kODErrorSessionProxyIPUnreachable`: The provided kODSessionProxyAddress did not respond."
    case kODErrorSessionProxyUnknownHost:
        return "`kODErrorSessionProxyUnknownHost`: The provided kODSessionProxyAddress cannot be resolved."
    case kODErrorNodeUnknownName:
        return "`kODErrorNodeUnknownName`: The node name provided does not exist and cannot be opened."
    case kODErrorNodeUnknownType:
        return "`kODErrorNodeUnknownType`: The node type provided is not a known value."
    case kODErrorNodeConnectionFailed:
        return "`kODErrorNodeConnectionFailed`: A node connection failed."
    case kODErrorNodeUnknownHost:
        return "`kODErrorNodeUnknownHost`: An invalid host is provided."
    case kODErrorQuerySynchronize:
        return "`kODErrorQuerySynchronize`: A synchronize has been initiated."
    case kODErrorQueryInvalidMatchType:
        return "`kODErrorQueryInvalidMatchType`: An invalid match type is provided in a query."
    case kODErrorQueryUnsupportedMatchType:
        return "`kODErrorQueryUnsupportedMatchType`: The plugin does not support the requested match type."
    case kODErrorQueryTimeout:
        return "`kODErrorQueryTimeout`: The query timed out during the request."
    case kODErrorRecordReadOnlyNode:
        return "`kODErrorRecordReadOnlyNode`: The record cannot be modified."
    case kODErrorRecordPermissionError:
        return "`kODErrorRecordPermissionError`: The changes requested were denied due to insufficient permissions."
    case kODErrorRecordParameterError:
        return "`kODErrorRecordParameterError`: An invalid parameter was provided."
    case kODErrorRecordInvalidType:
        return "`kODErrorRecordInvalidType`: An invalid record type was provided."
    case kODErrorRecordAlreadyExists:
        return "`kODErrorRecordAlreadyExists`: The record create failed because the record already exists."
    case kODErrorRecordTypeDisabled:
        return "`kODErrorRecordTypeDisabled`: The particular record type is disabled by policy for a plugin."
    case kODErrorRecordAttributeUnknownType:
        return "`kODErrorRecordAttributeUnknownType`: An unknown attribute type is provided."
    case kODErrorRecordAttributeNotFound:
        return "`kODErrorRecordAttributeNotFound`: The requested attribute is not found in the record."
    case kODErrorRecordAttributeValueSchemaError:
        return "`kODErrorRecordAttributeValueSchemaError`: An attribute value does not meet schema requirements."
    case kODErrorRecordAttributeValueNotFound:
        return "`kODErrorRecordAttributeValueNotFound`: An attribute value is not found in a record."
    case kODErrorCredentialsInvalid:
        return "`kODErrorCredentialsInvalid`: The provided credentials are invalid with the current node."
    case kODErrorCredentialsMethodNotSupported:
        return "`kODErrorCredentialsMethodNotSupported`: A particular extended method is not supported by the node."
    case kODErrorCredentialsNotAuthorized:
        return "`kODErrorCredentialsNotAuthorized`: An operation such as changing a password is not authorized with current privileges."
    case kODErrorCredentialsParameterError:
        return "`kODErrorCredentialsParameterError`: A parameter provided is invalid."
    case kODErrorCredentialsOperationFailed:
        return "`kODErrorCredentialsOperationFailed`: The requested operation failed (usually due to some unrecoverable error)."
    case kODErrorCredentialsServerUnreachable:
        return "`kODErrorCredentialsServerUnreachable`: The authentication server is not reachable."
    case kODErrorCredentialsServerNotFound:
        return "`kODErrorCredentialsServerNotFound`: The authentication server could not be found for the requested operation."
    case kODErrorCredentialsServerError:
        return "`kODErrorCredentialsServerError`: The authentication server encountered an error."
    case kODErrorCredentialsServerTimeout:
        return "`kODErrorCredentialsServerTimeout`: The authentication server timed out."
    case kODErrorCredentialsContactPrimary:
        return "`kODErrorCredentialsContactPrimary`: The authentication server is not the primary and the operation requires the primary."
    case kODErrorCredentialsServerCommunicationError:
        return "`kODErrorCredentialsServerCommunicationError`: The authentication server had a communication error."
    case kODErrorCredentialsAccountNotFound:
        return "`kODErrorCredentialsAccountNotFound`: The authentication server could not find the provided account."
    case kODErrorCredentialsAccountDisabled:
        return "`kODErrorCredentialsAccountDisabled`: The account is disabled."
    case kODErrorCredentialsAccountExpired:
        return "`kODErrorCredentialsAccountExpired`: The account has expired."
    case kODErrorCredentialsAccountInactive:
        return "`kODErrorCredentialsAccountInactive`: The account is inactive."
    case kODErrorCredentialsAccountTemporarilyLocked:
        return "`kODErrorCredentialsAccountTemporarilyLocked`: The account is in backoff (verification attempts ignored for a period of time)."
    case kODErrorCredentialsAccountLocked:
        return "`kODErrorCredentialsAccountLocked`: The account is locked due to too many verification failures."
    case kODErrorCredentialsPasswordExpired:
        return "`kODErrorCredentialsPasswordExpired`: The password has expired and must be changed."
    case kODErrorCredentialsPasswordChangeRequired:
        return "`kODErrorCredentialsPasswordChangeRequired`: A password change is required."
    case kODErrorCredentialsPasswordQualityFailed:
        return "`kODErrorCredentialsPasswordQualityFailed`: The password provided for change did not meet quality minimum requirements."
    case kODErrorCredentialsPasswordTooShort:
        return "`kODErrorCredentialsPasswordTooShort`: The provided password is too short."
    case kODErrorCredentialsPasswordTooLong:
        return "`kODErrorCredentialsPasswordTooLong`: The provided password is too long."
    case kODErrorCredentialsPasswordNeedsLetter:
        return "`kODErrorCredentialsPasswordNeedsLetter`: The password needs a letter."
    case kODErrorCredentialsPasswordNeedsDigit:
        return "`kODErrorCredentialsPasswordNeedsDigit`: The password needs a digit."
    case kODErrorCredentialsPasswordChangeTooSoon:
        return "`kODErrorCredentialsPasswordChangeTooSoon`: An attempt to change a password is made too soon before the last change."
    case kODErrorCredentialsPasswordUnrecoverable:
        return "`kODErrorCredentialsPasswordUnrecoverable`: The password was not recoverable from the authentication database."
    case kODErrorCredentialsInvalidLogonHours:
        return "`kODErrorCredentialsInvalidLogonHours`: An account attempts to log in outside of set logon hours."
    case kODErrorCredentialsInvalidComputer:
        return "`kODErrorCredentialsInvalidComputer`: An account attempts to log in to a computer they are not authorized."
    case kODErrorPolicyUnsupported:
        return "`kODErrorPolicyUnsupported`: All requested policies were not supported."
    case kODErrorPolicyOutOfRange:
        return "`kODErrorPolicyOutOfRange`: The policy value was beyond the allowed range."
    case kODErrorPluginOperationNotSupported:
        return "`kODErrorPluginOperationNotSupported`: The plugin does not support the requested operation."
    case kODErrorPluginError:
        return "`kODErrorPluginError`: The plugin has encountered some undefined error."
    case kODErrorDaemonError:
        return "`kODErrorDaemonError`: Some error occurred inside the daemon."
    case kODErrorPluginOperationTimeout:
        return "`kODErrorPluginOperationTimeout`: An operation exceeds an imposed timeout."
    default:
        return "Unknown"
    }
}


/// The name of an Open Directory group member's type, as the Security Extension records an `od_group_add` or
/// `od_group_remove` event's `member`.
///
/// - Parameter type: The member's `es_od_member_type_t`.
/// - Returns: The type's name, or `UNKNOWN`.
func odMemberTypeName(_ type: es_od_member_type_t) -> String {
    switch type {
    case ES_OD_MEMBER_TYPE_USER_NAME: "ES_OD_MEMBER_TYPE_USER_NAME"
    case ES_OD_MEMBER_TYPE_USER_UUID: "ES_OD_MEMBER_TYPE_USER_UUID"
    case ES_OD_MEMBER_TYPE_GROUP_UUID: "ES_OD_MEMBER_TYPE_GROUP_UUID"
    default: "UNKNOWN"
    }
}
