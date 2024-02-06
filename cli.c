#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdbool.h>
#include "yara.h"
#include "3S.h"

int main(int argc, char* argv[]) {
    // Confirm proper input
    if (argc != 3) {
        fprintf(stderr, "USAGE: 3S YARA_RULE_FILE TARGET_DIR\n");
        exit(1);
    }

    // Load arguments
    char* yaraRuleFilename = argv[1];
    char* dirToScan = argv[2];

    // Load file from argument
    FILE* yaraRuleFile = fopen(yaraRuleFilename, "r");
    if (yaraRuleFile == NULL) {
        fprintf(stderr, "Opening file '%s' failed. Exiting...\n", yaraRuleFilename);
        exit(1);
    }

    // Load directory from argument
    // code derived from stackoverflow.com/questions/4204666
    DIR* d;
    d = opendir(dirToScan);
    if (d == NULL) {
        fprintf(stderr, "Directory access failed. Exiting...\n");
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

    // Read rule file into YARA compiler
    int numErrs = yr_compiler_add_file(compiler, 
                                       yaraRuleFile, 
                                       NULL, 
                                       yaraRuleFilename);
    if (numErrs != 0) {
        fprintf(stderr,
                "YARA rule file '%s' processing failed with %d errors. Exiting...", 
                yaraRuleFilename, numErrs);
        exit(1);
    }

    // Pull compiled rules from the compiler
    YR_RULES* rules;
    int ruleGetRet = yr_compiler_get_rules(compiler, &rules);
    if (ruleGetRet != ERROR_SUCCESS) {
        fprintf(stderr, "Rule retrieval failed. Exiting...\n");
        exit(1);
    }

    // Send rules to calcNPercentileLength to get 90th percentile
    int percentile90 = calcNPercentileLength(rules, 90);

    /* RUN SIGNATURE SCANS TESTS */
    // Loop through each file in given directory
    struct dirent* dir;
    printf("BEGIN SCAN OF [%d] CHARACTER HEADERS AND FOOTERS:\n", percentile90);
    while ((dir = readdir(d)) != NULL) {
        // Run headTailScan on each file (ignore '.' and '..' files)
        char* dirFilename = dir->d_name;
        if (strcmp(dirFilename, ".") && strcmp(dirFilename, "..")) {
            // reconstruct full filepath to files
            char fullFilename[256];
            int success = sprintf(fullFilename, "%s/%s", dirToScan, dirFilename);
            assert(success > -1);  // ensure sprintf succeeded
            printf("\tScanning '%s' .....", fullFilename);
            
            bool matchFound = headTailScan(fullFilename, rules, percentile90);
            if (matchFound) printf(" SIGNATURE MATCH\n");
            else            printf("\n");

        }
    }
    closedir(d);
    
    // Shut down YARA, destroy compiler, close file, and exit
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
    fclose(yaraRuleFile);

    exit(0);
}
