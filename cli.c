#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdbool.h>
#include "yara.h"
#include "3S.h"
#include "cli.h"

int main(int argc, char* argv[]) {
    /************ INPUT VERIFICATION ************/
    // Confirm proper input
    if (argc != 3) {
        fprintf(stderr, "USAGE: 3S YARA_RULE_FILE TARGET_DIR\n");
        exit(1);
    }

    // Load arguments
    char* ruleDirToScan   = argv[1];
    char* targetDirToScan = argv[2];

    // Load rule directory and target directory from arguments
    // code derived from stackoverflow.com/questions/4204666
    DIR* dRule;
    dRule = opendir(ruleDirToScan);
    if (dRule == NULL) {
        fprintf(stderr, "Rule directory access failed. Exiting...\n");
        exit(1);
    }

    DIR* dTarget;
    dTarget = opendir(targetDirToScan);
    if (dTarget == NULL) {
        fprintf(stderr, "Target directory access failed. Exiting...\n");
        exit(1);
    }
    
    // Start YARA
    int initRet = yr_initialize();
    if (initRet != ERROR_SUCCESS) {
        fprintf(stderr, "YARA initialization failed. Exiting...\n");
        exit(1);
    }
    
    // Set up YARA compiler
    YR_COMPILER* compiler;
    int compRet = yr_compiler_create(&compiler);
    if (compRet != ERROR_SUCCESS) {
        fprintf(stderr, "YARA compiler creation failed. Exiting...\n");
        exit(1);
    }


    /************ LOAD RULE FILES ************/
    /* Read directory of rule files into YARA compiler */
    // Loop through each rule file in given directory
    printf("BEGIN READING OF RULE FILES\n");
    struct dirent* ruleDir;
    while ((ruleDir = readdir(dRule)) != NULL) {
        char* dirFilename = ruleDir->d_name;
        if (strcmp(dirFilename, ".") && strcmp(dirFilename, "..")) {
            // reconstruct full filepath to file
            char fullFilename[256];
            int success = sprintf(fullFilename, "%s/%s", ruleDirToScan, dirFilename);
            assert(success > -1);  // ensure sprintf succeeded
            printf("\tReading rule file '%s'\n", fullFilename);
            
            // Attempt to open the file
            FILE* yaraRuleFile = fopen(fullFilename, "r");
            if (yaraRuleFile == NULL) {
                fprintf(stderr, "Opening rule file '%s' failed. Exiting...\n", 
                        fullFilename);
                exit(1);
            }

            // Attempt to read the file into the YARA compiler
            int numErrs = yr_compiler_add_file(compiler, 
                                               yaraRuleFile, 
                                               NULL, 
                                               fullFilename);
            if (numErrs != 0) {
                fprintf(stderr,
                        "YARA rule file '%s' processing failed with %d errors. Exiting...\n", 
                        fullFilename, numErrs);
                exit(1);
            }

            // Close the file, move to the next in the directory
            fclose(yaraRuleFile);
        }
    }
    fprintf(stderr, "\n");
    closedir(dRule);

    // Pull compiled rules from the compiler
    YR_RULES* rules;
    int ruleGetRet = yr_compiler_get_rules(compiler, &rules);
    if (ruleGetRet != ERROR_SUCCESS) {
        fprintf(stderr, "Rule retrieval failed. Exiting...\n");
        exit(1);
    }

    
    /************ RUNNING SCAN TESTS ************/
    bool print = true;   // debug print of files as scan progresses

    /* FULL FILE TEST */
    // Loop through each file in given directory
    struct dirent* targetDir;
    printf("BEGIN SCAN OF FULL FILES:\n");
    int numMatch = 0;
    while ((targetDir = readdir(dTarget)) != NULL) {
        // Run headTailScan on each file (ignore '.' and '..' files)
        char* dirFilename = targetDir->d_name;
        if (strcmp(dirFilename, ".") && strcmp(dirFilename, "..")) {
            // reconstruct full filepath to files
            char fullFilename[256];
            int success = sprintf(fullFilename, "%s/%s", targetDirToScan, dirFilename);
            assert(success > -1);  // ensure sprintf succeeded

            if (print) printf("\tScanning '%s' ..... ", fullFilename);
            
            // Scan
            bool matchFound = fullScan(fullFilename, rules);

            // Track success/failure of scan
            if (matchFound) {
                numMatch++;
                if (print) printf("SIGNATURE MATCH\n");   
            }
            else if (print) printf("\n");
        }
    }
    rewinddir(dTarget);
    printf("numMatch=%d\n\n", numMatch);
    
    /* PERCENTILE TESTS */
    // Send rules to calcNPercentileLength to get various percentile lengths
    int percentile90 = calcNPercentileLength(rules, 90);
    int percentile100 = calcNPercentileLength(rules, 100);
    int doubleLongest = percentile100 * 2;

    // Run tests, report results
    printf("numMatch=%d\n\n", percentileTest(dTarget,
                                         targetDirToScan,
                                         percentile90,
                                         rules,
                                         print));
    rewinddir(dTarget);
    printf("numMatch=%d\n\n", percentileTest(dTarget,
                                         targetDirToScan, 
                                         percentile100, 
                                         rules, 
                                         print));
    rewinddir(dTarget);
    printf("numMatch=%d\n\n", percentileTest(dTarget, 
                                         targetDirToScan,
                                        doubleLongest, 
                                         rules, 
                                         print));
    rewinddir(dTarget);
    

    /************ EXITING ************/
    // Shut down YARA, destroy compiler, and exit
    closedir(dTarget);
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
    exit(0);
}



int percentileTest(DIR* dTarget, 
                   char* targetDirToScan,
                   int headFootLen,
                   YR_RULES* rules,
                   bool print) {
    struct dirent* targetDir;
    printf("BEGIN SCAN OF [%d] CHARACTER HEADERS AND FOOTERS:\n", headFootLen);
    int numMatch = 0;
    while ((targetDir = readdir(dTarget)) != NULL) {
        // Run headTailScan on each file (ignore '.' and '..' files)
        char* dirFilename = targetDir->d_name;
        if (strcmp(dirFilename, ".") && strcmp(dirFilename, "..")) {
            // reconstruct full filepath to files
            char fullFilename[256];
            int success = sprintf(fullFilename, "%s/%s", targetDirToScan, dirFilename);
            assert(success > -1);  // ensure sprintf succeeded
            
            if (print) printf("\tScanning '%s' ..... ", fullFilename);
            
            // Scan
            bool matchFound = headTailScan(fullFilename, rules, headFootLen);

            // Track success/failure of scan
            if (matchFound) {
                numMatch++;
                if (print) printf("SIGNATURE MATCH\n");   
            }
            else if (print) printf("\n");
        }
    }
    return numMatch;
}

