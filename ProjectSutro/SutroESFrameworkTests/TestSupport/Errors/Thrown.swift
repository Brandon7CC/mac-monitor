//
//  Thrown.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//


// MARK: - What a failure is
extension Result {
    /// The error, or `nil` for a success.
    var failure: Failure? {
        guard case .failure(let error) = self else { return nil }
        return error
    }
}


// MARK: - What a call throws
/// The error a call throws, for comparing with the one expected: `nil` when it returns, or throws another type.
///
/// - Parameters:
///   - type: The error's type, when nothing else says it, as in `thrown(CocoaError.self) { … }?.code`.
///   - body: The call.
/// - Returns: The error, if it's an `E`.
func thrown<E: Error, T>(_ type: E.Type = E.self, by body: () throws -> T) -> E? {
    Result(catching: body).failure as? E
}
