#include <stdio.h>
#include <stdlib.h>
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
    
    // Start YARA
    int initRet = yr_initialize();
    if (initRet != ERROR_SUCCESS) {
        fprintf(stderr, "YARA initialization failed. Exiting...\n");
        exit(1);
    }
    
    // TODO: shift compiler creation and rule reading into 3S function
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
        fprintf(stderr, "YARA rule file '%s' processing failed with %d errors. Exiting...", 
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

    // Send rules to calc90PercentileLength
    int percentile90 = calcNPercentileLength(rules, 90);

    // Shut down YARA, destroy compiler, close file, and exit
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
    fclose(yaraRuleFile);

    // DEBUG
    printf("Hello World\n");
    exciseHeadTail("testfile", 5);
    printf("90th percentile is: %d\n", percentile90);

    exit(0);
}
