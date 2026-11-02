//
//  arm64e-test-host.m
//  Mac Monitor
//
//  Created by Brandon Dalton on 10/5/26.
//
//  Runs an .xctest bundle's tests in an arm64e process, which xcodebuild test can't do: Xcode's test runner (xctest)
//  has only x86_64 and arm64 slices. Scripts/test-arm64e.sh builds it and runs SutroESFrameworkTests with it.
//
//  Usage: arm64e-test-host <bundle.xctest> [TestClass | TestClass/testMethod]
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach/machine.h>
#include <ptrauth.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#if !__has_feature(ptrauth_calls)
#error "Build the test host for arm64e: clang -arch arm64e"
#endif

/// Whether this process signs pointers. macOS 26 and later run arm64e code with pointer authentication on; earlier
/// versions run it with the keys off, where signing leaves a pointer as it was.
///
/// - Returns: `YES` when signing a pointer changes it.
static BOOL PointerAuthenticationIsOn(void) {
    void *address = (void *)0x100000000ULL;
    return ptrauth_sign_unauthenticated(address, ptrauth_key_asia, 0) != address;
}

/// Counts the images dyld loaded from the built products, and reports the first one that isn't an arm64e slice, so
/// the tests can't pass on a framework loaded from somewhere else, or on an arm64 slice.
///
/// - Parameter folder: The real path of the built products' folder, ending in `/`.
/// - Returns: The number of images loaded from `folder`, or -1 after printing one that isn't arm64e.
static int CountArm64eImages(const char *folder) {
    int count = 0;
    for (uint32_t index = 0; index < _dyld_image_count(); index++) {
        char path[PATH_MAX];
        // Libraries in the shared cache have no file to resolve, and none of them is ours.
        if (realpath(_dyld_get_image_name(index), path) == NULL || strncmp(path, folder, strlen(folder)) != 0) {
            continue;
        }
        const struct mach_header *header = _dyld_get_image_header(index);
        if (header->cputype != CPU_TYPE_ARM64 || (header->cpusubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E) {
            fprintf(stderr, "not an arm64e slice (cpusubtype 0x%x): %s\n", header->cpusubtype, path);
            return -1;
        }
        count++;
    }
    return count;
}

/// Loads the bundle, checks that it and the framework it links run as arm64e with pointer authentication on, and
/// runs its tests, or one class or test of them.
///
/// - Parameters:
///   - argc: The number of arguments: 2, or 3 with a test.
///   - argv: The host, the `.xctest` bundle, and optionally a test class or `Class/testMethod`.
/// - Returns: 0 when every test passed, 1 when one failed, `EX_USAGE` when no test ran (none matches the one given),
///   or another `sysexits.h` code when the tests can't run as arm64e.
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 2 || argc > 3) {
            fprintf(stderr, "usage: %s <bundle.xctest> [TestClass | TestClass/testMethod]\n", argv[0]);
            return EX_USAGE;
        }
        if (!PointerAuthenticationIsOn()) {
            fprintf(stderr, "pointer authentication is off in this process: run the tests on macOS 26 or later\n");
            return EX_UNAVAILABLE;
        }
        char path[PATH_MAX];
        if (realpath(argv[1], path) == NULL) {
            fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
            return EX_NOINPUT;
        }
        NSError *error = nil;
        if (![[NSBundle bundleWithPath:@(path)] loadAndReturnError:&error]) {
            // dyld's reason, such as a library without an arm64e slice, is only in the debug description.
            NSString *reason = error.userInfo[NSDebugDescriptionErrorKey] ?: error.localizedDescription;
            fprintf(stderr, "can't load %s: %s\n", path, reason.UTF8String);
            return EX_NOINPUT;
        }
        NSString *folder = [@(path).stringByDeletingLastPathComponent stringByAppendingString:@"/"];
        int images = CountArm64eImages(folder.fileSystemRepresentation);
        if (images < 2) {
            if (images >= 0) { fprintf(stderr, "expected the bundle and a framework from %s\n", folder.UTF8String); }
            return EX_SOFTWARE;
        }
        fprintf(stderr, "arm64e with pointer authentication on: %d images from %s\n", images, folder.UTF8String);

        XCTestSuite *suite = argc == 3 ? [XCTestSuite testSuiteForTestCaseWithName:@(argv[2])]
                                       : [XCTestSuite defaultTestSuite];
        [suite runTest];
        // XCTest runs, and passes, an empty suite for a name that matches no test.
        if (suite.testRun.executionCount == 0) {
            if (argc == 3) {
                fprintf(stderr, "no test matches %s\n", argv[2]);
            } else {
                fprintf(stderr, "no test in %s\n", path);
            }
            return EX_USAGE;
        }
        return suite.testRun.hasSucceeded ? EXIT_SUCCESS : EXIT_FAILURE;
    }
}
