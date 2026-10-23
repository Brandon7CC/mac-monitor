//
//  PredicateBridge.m
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

#import "PredicateBridge.h"

NSErrorDomain const PredicateBridgeErrorDomain = @"com.swiftlydetecting.agent.predicate";

/// An exception as an error.
///
/// - Parameter exception: The exception.
/// - Returns: An error whose description is the exception's reason.
static NSError *PredicateBridgeError(NSException *exception) {
    NSString *reason = exception.reason ?: exception.name;
    return [NSError errorWithDomain:PredicateBridgeErrorDomain code:0
                           userInfo:@{NSLocalizedDescriptionKey: reason}];
}

@implementation PredicateBridge

+ (nullable NSPredicate *)predicateWithFormat:(NSString *)format error:(NSError **)error {
    @try {
        // An empty array, not nil: with nil, a %@ in the format reads an argument that isn't there and crashes.
        // With none, it raises "Insufficient arguments", which is caught.
        return [NSPredicate predicateWithFormat:format argumentArray:@[]];
    } @catch (NSException *exception) {
        if (error) *error = PredicateBridgeError(exception);
        return nil;
    }
}

+ (BOOL)evaluate:(NSPredicate *)predicate withObject:(nullable id)object matches:(BOOL *)matches
           error:(NSError **)error {
    @try {
        *matches = [predicate evaluateWithObject:object];
        return YES;
    } @catch (NSException *exception) {
        if (error) *error = PredicateBridgeError(exception);
        return NO;
    }
}

@end
