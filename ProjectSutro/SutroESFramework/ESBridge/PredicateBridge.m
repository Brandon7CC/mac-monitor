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

+ (BOOL)evaluate:(NSPredicate *)predicate withObject:(nullable id)object
       variables:(nullable NSDictionary<NSString *, id> *)variables error:(NSError **)error {
    @try {
        return variables ? [predicate evaluateWithObject:object substitutionVariables:variables]
            : [predicate evaluateWithObject:object];
    } @catch (NSException *exception) {
        if (error) *error = PredicateBridgeError(exception);
        return NO;
    }
}

+ (nullable NSArray *)filter:(NSArray *)candidates withPredicate:(NSPredicate *)predicate object:(nullable id)object
                    variable:(NSString *)variable error:(NSError **)error {
    @try {
        // One dictionary for every candidate: a search compares up to a million pairs.
        NSMutableArray *matching = [NSMutableArray array];
        NSMutableDictionary *variables = [NSMutableDictionary dictionaryWithCapacity:1];
        for (id candidate in candidates) {
            variables[variable] = candidate;
            if ([predicate evaluateWithObject:object substitutionVariables:variables]) [matching addObject:candidate];
        }
        return matching;
    } @catch (NSException *exception) {
        if (error) *error = PredicateBridgeError(exception);
        return nil;
    }
}

+ (nullable id)evaluateExpression:(NSExpression *)expression withObject:(nullable id)object
                        variables:(nullable NSDictionary<NSString *, id> *)variables error:(NSError **)error {
    @try {
        // An expression reads its variables from the context.
        NSMutableDictionary *context = variables ? [variables mutableCopy] : nil;
        return [expression expressionValueWithObject:object context:context];
    } @catch (NSException *exception) {
        if (error) *error = PredicateBridgeError(exception);
        return nil;
    }
}

@end
