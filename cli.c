#include <stdio.h>
#include <stdlib.h>
#include "yara.h"
#include "3S.h"

int main(int argc, char* argv[]) {
    // Confirm proper input
    if (argc != 3) {
        printf("USAGE: 3S YARA_RULE_FILE TARGET_DIR\n");
        exit(1);
    }
    char* yaraRuleFile = argv[1];
    char* dirToScan = argv[2];

    // Load Yara rules from file
    yr_initialize();
    printf("Hello World\n");
    exciseHeadTail("testfile", 5);

    exit(0);
}
