//
//  ODHelpers.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/29/23.
//

import Foundation


/// The name and meaning of an Open Directory error code, from `odconstants.h`.
///
/// - Parameter errorCode: An Open Directory event's `error_code`.
/// - Returns: The error's name and description, or `Unknown` for a code `odconstants.h` doesn't define.
public func decodeODErrorCode(_ errorCode: Int) -> String {
    odErrorNames.name(of: errorCode)
}

/// `ODFrameworkErrors`: each Open Directory error code's name and meaning.
private let odErrorNames = ConstantNames([
    kODErrorSuccess.rawValue: "`kODErrorSuccess`: The operation was successful.",
    kODErrorSessionLocalOnlyDaemonInUse.rawValue:
        "`kODErrorSessionLocalOnlyDaemonInUse`: A Local Only session was initiated and is still active.",
    kODErrorSessionNormalDaemonInUse.rawValue:
        "`kODErrorSessionNormalDaemonInUse`: The Normal daemon is still in use but request was issued for Local only.",
    kODErrorSessionDaemonNotRunning.rawValue: "`kODErrorSessionDaemonNotRunning`: The daemon is not running.",
    kODErrorSessionDaemonRefused.rawValue: "`kODErrorSessionDaemonRefused`: The daemon refused the session.",
    kODErrorSessionProxyCommunicationError.rawValue:
        "`kODErrorSessionProxyCommunicationError`: There was a communication error with the remote daemon.",
    kODErrorSessionProxyVersionMismatch.rawValue:
        "`kODErrorSessionProxyVersionMismatch`: Versions mismatch between the remote daemon and local framework.",
    kODErrorSessionProxyIPUnreachable.rawValue:
        "`kODErrorSessionProxyIPUnreachable`: The provided kODSessionProxyAddress did not respond.",
    kODErrorSessionProxyUnknownHost.rawValue:
        "`kODErrorSessionProxyUnknownHost`: The provided kODSessionProxyAddress cannot be resolved.",
    kODErrorNodeUnknownName.rawValue:
        "`kODErrorNodeUnknownName`: The node name provided does not exist and cannot be opened.",
    kODErrorNodeUnknownType.rawValue: "`kODErrorNodeUnknownType`: The node type provided is not a known value.",
    kODErrorNodeConnectionFailed.rawValue: "`kODErrorNodeConnectionFailed`: A node connection failed.",
    kODErrorNodeUnknownHost.rawValue: "`kODErrorNodeUnknownHost`: An invalid host is provided.",
    kODErrorQuerySynchronize.rawValue: "`kODErrorQuerySynchronize`: A synchronize has been initiated.",
    kODErrorQueryInvalidMatchType.rawValue:
        "`kODErrorQueryInvalidMatchType`: An invalid match type is provided in a query.",
    kODErrorQueryUnsupportedMatchType.rawValue:
        "`kODErrorQueryUnsupportedMatchType`: The plugin does not support the requested match type.",
    kODErrorQueryTimeout.rawValue: "`kODErrorQueryTimeout`: The query timed out during the request.",
    kODErrorRecordReadOnlyNode.rawValue: "`kODErrorRecordReadOnlyNode`: The record cannot be modified.",
    kODErrorRecordPermissionError.rawValue:
        "`kODErrorRecordPermissionError`: The changes requested were denied due to insufficient permissions.",
    kODErrorRecordParameterError.rawValue: "`kODErrorRecordParameterError`: An invalid parameter was provided.",
    kODErrorRecordInvalidType.rawValue: "`kODErrorRecordInvalidType`: An invalid record type was provided.",
    kODErrorRecordAlreadyExists.rawValue:
        "`kODErrorRecordAlreadyExists`: The record create failed because the record already exists.",
    kODErrorRecordTypeDisabled.rawValue:
        "`kODErrorRecordTypeDisabled`: The particular record type is disabled by policy for a plugin.",
    kODErrorRecordAttributeUnknownType.rawValue:
        "`kODErrorRecordAttributeUnknownType`: An unknown attribute type is provided.",
    kODErrorRecordAttributeNotFound.rawValue:
        "`kODErrorRecordAttributeNotFound`: The requested attribute is not found in the record.",
    kODErrorRecordAttributeValueSchemaError.rawValue:
        "`kODErrorRecordAttributeValueSchemaError`: An attribute value does not meet schema requirements.",
    kODErrorRecordAttributeValueNotFound.rawValue:
        "`kODErrorRecordAttributeValueNotFound`: An attribute value is not found in a record.",
    kODErrorCredentialsInvalid.rawValue:
        "`kODErrorCredentialsInvalid`: The provided credentials are invalid with the current node.",
    kODErrorCredentialsMethodNotSupported.rawValue:
        "`kODErrorCredentialsMethodNotSupported`: A particular extended method is not supported by the node.",
    kODErrorCredentialsNotAuthorized.rawValue: "`kODErrorCredentialsNotAuthorized`: An operation such as changing a "
        + "password is not authorized with current privileges.",
    kODErrorCredentialsParameterError.rawValue: "`kODErrorCredentialsParameterError`: A parameter provided is invalid.",
    kODErrorCredentialsOperationFailed.rawValue: "`kODErrorCredentialsOperationFailed`: The requested operation failed "
        + "(usually due to some unrecoverable error).",
    kODErrorCredentialsServerUnreachable.rawValue:
        "`kODErrorCredentialsServerUnreachable`: The authentication server is not reachable.",
    kODErrorCredentialsServerNotFound.rawValue: "`kODErrorCredentialsServerNotFound`: The authentication server could "
        + "not be found for the requested operation.",
    kODErrorCredentialsServerError.rawValue:
        "`kODErrorCredentialsServerError`: The authentication server encountered an error.",
    kODErrorCredentialsServerTimeout.rawValue:
        "`kODErrorCredentialsServerTimeout`: The authentication server timed out.",
    kODErrorCredentialsContactPrimary.rawValue: "`kODErrorCredentialsContactPrimary`: The authentication server is not "
        + "the primary and the operation requires the primary.",
    kODErrorCredentialsServerCommunicationError.rawValue:
        "`kODErrorCredentialsServerCommunicationError`: The authentication server had a communication error.",
    kODErrorCredentialsAccountNotFound.rawValue:
        "`kODErrorCredentialsAccountNotFound`: The authentication server could not find the provided account.",
    kODErrorCredentialsAccountDisabled.rawValue: "`kODErrorCredentialsAccountDisabled`: The account is disabled.",
    kODErrorCredentialsAccountExpired.rawValue: "`kODErrorCredentialsAccountExpired`: The account has expired.",
    kODErrorCredentialsAccountInactive.rawValue: "`kODErrorCredentialsAccountInactive`: The account is inactive.",
    kODErrorCredentialsAccountTemporarilyLocked.rawValue: "`kODErrorCredentialsAccountTemporarilyLocked`: The account "
        + "is in backoff (verification attempts ignored for a period of time).",
    kODErrorCredentialsAccountLocked.rawValue:
        "`kODErrorCredentialsAccountLocked`: The account is locked due to too many verification failures.",
    kODErrorCredentialsPasswordExpired.rawValue:
        "`kODErrorCredentialsPasswordExpired`: The password has expired and must be changed.",
    kODErrorCredentialsPasswordChangeRequired.rawValue:
        "`kODErrorCredentialsPasswordChangeRequired`: A password change is required.",
    kODErrorCredentialsPasswordQualityFailed.rawValue: "`kODErrorCredentialsPasswordQualityFailed`: The password "
        + "provided for change did not meet quality minimum requirements.",
    kODErrorCredentialsPasswordTooShort.rawValue:
        "`kODErrorCredentialsPasswordTooShort`: The provided password is too short.",
    kODErrorCredentialsPasswordTooLong.rawValue:
        "`kODErrorCredentialsPasswordTooLong`: The provided password is too long.",
    kODErrorCredentialsPasswordNeedsLetter.rawValue:
        "`kODErrorCredentialsPasswordNeedsLetter`: The password needs a letter.",
    kODErrorCredentialsPasswordNeedsDigit.rawValue:
        "`kODErrorCredentialsPasswordNeedsDigit`: The password needs a digit.",
    kODErrorCredentialsPasswordChangeTooSoon.rawValue: "`kODErrorCredentialsPasswordChangeTooSoon`: An attempt to "
        + "change a password is made too soon before the last change.",
    kODErrorCredentialsPasswordUnrecoverable.rawValue: "`kODErrorCredentialsPasswordUnrecoverable`: The password was "
        + "not recoverable from the authentication database.",
    kODErrorCredentialsInvalidLogonHours.rawValue:
        "`kODErrorCredentialsInvalidLogonHours`: An account attempts to log in outside of set logon hours.",
    kODErrorCredentialsInvalidComputer.rawValue:
        "`kODErrorCredentialsInvalidComputer`: An account attempts to log in to a computer they are not authorized.",
    kODErrorPolicyUnsupported.rawValue: "`kODErrorPolicyUnsupported`: All requested policies were not supported.",
    kODErrorPolicyOutOfRange.rawValue: "`kODErrorPolicyOutOfRange`: The policy value was beyond the allowed range.",
    kODErrorPluginOperationNotSupported.rawValue:
        "`kODErrorPluginOperationNotSupported`: The plugin does not support the requested operation.",
    kODErrorPluginError.rawValue: "`kODErrorPluginError`: The plugin has encountered some undefined error.",
    kODErrorDaemonError.rawValue: "`kODErrorDaemonError`: Some error occurred inside the daemon.",
    kODErrorPluginOperationTimeout.rawValue:
        "`kODErrorPluginOperationTimeout`: An operation exceeds an imposed timeout.",
], unknown: "Unknown")


// MARK: - Names of Open Directory values
/// The names of Open Directory enums' values: `member_string`, `record_type_string` and `account_type_string`.
extension ConstantNames {
    /// `es_od_member_type_t`: the type of an `od_group_add` or `od_group_remove` event's member.
    static let memberType = ConstantNames([
        ES_OD_MEMBER_TYPE_USER_NAME.rawValue: "ES_OD_MEMBER_TYPE_USER_NAME",
        ES_OD_MEMBER_TYPE_USER_UUID.rawValue: "ES_OD_MEMBER_TYPE_USER_UUID",
        ES_OD_MEMBER_TYPE_GROUP_UUID.rawValue: "ES_OD_MEMBER_TYPE_GROUP_UUID",
    ])
    
    /// `es_od_record_type_t`: the type of the record an `od_attribute_value_add` event changes.
    static let recordType = ConstantNames([
        ES_OD_RECORD_TYPE_USER.rawValue: "USER",
        ES_OD_RECORD_TYPE_GROUP.rawValue: "GROUP",
    ])
    
    /// `es_od_account_type_t`: the type of the account whose password an `od_modify_password` event changes.
    static let accountType = ConstantNames([
        ES_OD_ACCOUNT_TYPE_USER.rawValue: "ES_OD_ACCOUNT_TYPE_USER",
        ES_OD_ACCOUNT_TYPE_COMPUTER.rawValue: "ES_OD_ACCOUNT_TYPE_COMPUTER",
    ], unknown: "UNKNOWN_ACCOUNT_TYPE")
}
