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

/// Evaluate a predicate on an object.
///
/// - Parameters:
///   - predicate: The predicate.
///   - object: What it's evaluated on.
///   - matches: Set to whether the object matches.
///   - error: Why it couldn't be evaluated.
/// - Returns: `YES` if it was evaluated, else `NO` with `error` set.
+ (BOOL)evaluate:(NSPredicate *)predicate withObject:(nullable id)object matches:(BOOL *)matches
           error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END

#endif /* PredicateBridge_h */
