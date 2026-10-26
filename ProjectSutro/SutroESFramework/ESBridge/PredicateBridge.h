//
//  PredicateBridge.h
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

#ifndef PredicateBridge_h
#define PredicateBridge_h

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// The domain of the errors ``PredicateBridge`` returns. The code is always 0, and the description is the exception's
/// reason.
FOUNDATION_EXPORT NSErrorDomain const PredicateBridgeErrorDomain;

/// `NSPredicate` for Swift. `NSPredicate` raises an Objective-C exception for a format it can't parse, or one it can't
/// evaluate on an object (`MATCHES` on a number), and Swift can't catch one: the process would end. These catch it
/// here, in Objective-C, and return it as an error.
@interface PredicateBridge : NSObject

/// A predicate from its format, which takes no arguments: a format with `%@`, `%K` or `%d` outside quotes can't be
/// read.
///
/// - Parameters:
///   - format: The format, such as `process.executable.path ENDSWITH "/curl"`.
///   - error: Why it can't be parsed.
/// - Returns: The predicate, or `nil` with `error` set.
+ (nullable NSPredicate *)predicateWithFormat:(NSString *)format error:(NSError **)error;

/// Evaluate a predicate on an object, with its variables (`$e`) bound if it has any. In Swift it returns whether the
/// object matches, and throws why it couldn't be evaluated.
///
/// - Parameters:
///   - predicate: The predicate.
///   - object: What it's evaluated on.
///   - variables: Each variable's value, by name, or `nil` for none.
///   - error: Why it couldn't be evaluated.
/// - Returns: Does the object match? `NO` with `error` set if it couldn't be evaluated.
+ (BOOL)evaluate:(NSPredicate *)predicate withObject:(nullable id)object
       variables:(nullable NSDictionary<NSString *, id> *)variables error:(NSError **)error
    NS_SWIFT_NAME(evaluate(_:with:variables:)) __attribute__((swift_error(nonnull_error)));

/// The values a predicate matches with its variable bound to each, evaluated on one object: a `SUBQUERY`'s related
/// events that its conditions on both events match.
///
/// - Parameters:
///   - candidates: The values.
///   - predicate: The predicate.
///   - object: What it's evaluated on.
///   - variable: The variable's name, `e` for `$e`.
///   - error: Why it couldn't be evaluated.
/// - Returns: The values it matches, in order, or `nil` with `error` set.
+ (nullable NSArray *)filter:(NSArray *)candidates withPredicate:(NSPredicate *)predicate object:(nullable id)object
                    variable:(NSString *)variable error:(NSError **)error
    NS_SWIFT_NAME(filter(_:with:object:variable:));

/// Evaluate an expression on an object, such as a comparison's key path. In Swift it returns the value, and throws why
/// it couldn't be evaluated.
///
/// - Parameters:
///   - expression: The expression.
///   - object: What it's evaluated on.
///   - variables: Each variable's value, by name, or `nil` for none.
///   - error: Why it couldn't be evaluated.
/// - Returns: The expression's value, which may be `nil`, or `nil` with `error` set if it couldn't be evaluated.
+ (nullable id)evaluateExpression:(NSExpression *)expression withObject:(nullable id)object
                        variables:(nullable NSDictionary<NSString *, id> *)variables error:(NSError **)error
    NS_SWIFT_NAME(evaluate(_:with:variables:)) __attribute__((swift_error(nonnull_error)));

@end

NS_ASSUME_NONNULL_END

#endif /* PredicateBridge_h */
