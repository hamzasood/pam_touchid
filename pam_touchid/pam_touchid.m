//
//  pam_touchid.m
//  pam_touchid
//
//  Created by Hamza Sood on 18/11/2016.
//  Copyright © 2016 Hamza Sood. All rights reserved.
//

#import <dispatch/dispatch.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

// Defined below
static NSString *__nullable FindReason(int argc, const char **argv);


// Ignore requests for the stuff we don't support
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_IGNORE; }
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)   { return PAM_IGNORE; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_IGNORE; }

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    
    __block int result = PAM_AUTH_ERR;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    
    NSString *reason = FindReason(argc, argv);
    if (reason.length == 0)
        reason = @"perform an action that requires authentication";
    
    // The public policies use the calling process uid to filter fingerprints
    // sudo runs as root, and root probably won't have fingerprints enrolled
    // So use a policy that ignores uid
    [[[LAContext alloc]init]
     evaluatePolicy: 0x3f0
     localizedReason: reason
     reply:^(BOOL success, NSError * _Nullable error) {
         if (success) {
             result = PAM_SUCCESS;
         }
         else {
             fprintf(stderr, "%s\n", error.localizedDescription.UTF8String);
             result = PAM_AUTH_ERR;
         }
         dispatch_semaphore_signal(semaphore);
     }];
    
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return result;
}


// Parse the arguments and try to find the given reason
// Returns nil if it wasn't found
static NSString *FindReason(int argc, const char **argv) {
    
    // Unfortunately, the version of OpenPAM that ships with macOS doesn't have openpam_readword
    // So quoted expressions aren't handled correctly, and are still broken up by spaces
    // e.g. key="my value" becomes [key="my, value"]
    // So we need to parse the arguments manually
    
    const char *key = "reason=";
    size_t keyLen = strlen(key);
    
    int keyIdx = -1;
    for (int i = 0; i < argc; ++i) {
        if (strncmp(argv[i], key, keyLen) == 0) {
            keyIdx = i;
            break;
        }
    }
    
    if (keyIdx == -1)
        return nil;
    
    char firstChar = argv[keyIdx][keyLen];
    if (firstChar == '\'' || firstChar == '"') {
        // This is a quoted expression
        // So we need to loop over the remaining arguments and keep adding text until we find the end quote
        NSMutableString *result = [[NSMutableString alloc]init];
        
        // Index of the current argument in the loop
        int i = keyIdx;
        
        // String for the current argument in the loop
        // Start with the argument containing the key, but skip the key and the opening quote
        const char *p = argv[keyIdx] + keyLen + 1;
        
        while (true) {
            const char *endQuotePtr = strchr(p, firstChar);
            if (endQuotePtr) {
                // This argument contains the end quote
                // So add up to the quote and stop
                [result appendString:[[NSString alloc]initWithBytes:p
                                                             length:(endQuotePtr - p)
                                                           encoding:NSUTF8StringEncoding]];
                break;
            }
            else {
                // No end quote (yet)
                // So add the text and move on
                [result appendString:@(p)];
                
                if (i < argc-1) {
                    // There're more arguments to come
                    // Add a space and get the next values for i and p
                    [result appendString:@" "];
                    p = argv[++i];
                }
                else {
                    // This was the last argument
                    // So end the loop
                    break;
                }
            }
        }
        
        return result;
    }
    else {
        // This isn't a quoted expression
        // So just return the rest of the argument
        return @(argv[keyIdx] + keyLen);
    }
}
