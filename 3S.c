#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "yara.h"

/*
 *
 *
 * @param compiler YR_COMPILER which has already had a rule file added to it
 * @return the 90th percentile length on success, -1 on error
 */
int calc90PercentileLength(YR_RULES* rules) {
    assert(rules != NULL);

    // Cycle through rules, save len of each's longest string into a list
    YR_RULE* rule;

    /* TODO: shift to callback function
    yr_rules_foreach(rules, rule) {
        printf("\n\nRULE");
        // Cycle through strings for each rule, calculating the longest
        YR_STRING* string;
        int longestLen = 0;

        /* TODO: shift to a callback function
        yr_strings_foreach(rule, string) {
            int length = strlen(string);
            if (length > longestLen)
                longestLen = length;
            printf("\tSTRING: %s\n", string)
        }
        */
    }
    */

    // Clear memory
    yr_rules_destroy(rules);

    return 0;
}


/*
 * @brief Excises the beginning and end of file, returning it in an array.
 *
 * Cuts numChars characters from the beginning and end of a supplied file.
 * Trusts caller to open and close file.
 *
 * @param inFilename string name of the file from which portions will be cut
 * @param numChars the number of chars to cut from the start and end of a file
 * @return malloc'd string containing the beginning and ending characters;
 *         trusts callet to free string
 */
char* exciseHeadTail(char filename[], int numChars) {
    // Load file as binary
    FILE* file = fopen(filename, "rb");
    assert(file != NULL);

    // TODO: consider whether binary files require a special case

    // Allocate memory for the characters
    char* headTail = malloc(numChars * 2 + 1);  // +1 for \0
    assert(headTail != NULL);
    
    // Read the first n characters
    // TODO handle file length <= 2*numChars
    fseek(file, 0, SEEK_SET);
    fread(headTail, 1, numChars, file);

    // Read the last n characters, appending to those already in array
    // NB: for text files, newline will be read
    fseek(file, -numChars, SEEK_END);
    fread(&headTail[numChars], 1, numChars, file);
    headTail[2 * numChars] = '\0';

    // DEBUG 
    printf("%d head/tail characters: %s\n", numChars, headTail);

    return headTail;
}

/*
 * @brief Selects sections of a file to search, based on an ML model.
 *
 * Will be implemented once exciseHeadTail has been completed and
 * comprehensively tested.
 */
int smartExcise();

/*
 * @brief Runs Yara on a selected buffer.
 *
 * Runs Yara on a selected file -- intended for use on a file created by an
 * excise function.
 *
 * @param filename string name of file to be scanned
 * @param yaraFile string name of Yara rule file to be used
 */
int invokeYaraOnBuffer(char scan[], size_t scan_len, YR_RULES* rules) {
    // scan the given buffer
    yaraCallRet = yr_rules_scan_mem(rules,      // Rule file
                                    scan,       // Buffer to scan
                                    scan_len,   // Buffer length
                                    0,          // Flags
                                    NULL,       // TODO: write callback function
                                    NULL,       // TODO: look into user data
                                    1000);      // Timeout
    return 0;
}

