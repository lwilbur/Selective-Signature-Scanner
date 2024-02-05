#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "yara.h"

/*
 * Integer comparison function for use with qsort 
 * stackoverflow.com/questions/59890582
 */
int cmp_int(const void *va, const void *vb)
{
  int a = *(int *)va, b = *(int *) vb;
  return a < b ? -1 : a > b ? +1 : 0;
}

/*
 *
 *
 * @param compiler YR_COMPILER which has already had a rule file added to it
 * @return the 90th percentile length on success, -1 on error
 */
int calcNPercentileLength(YR_RULES* rules, int n) {
    assert(rules != NULL);
    assert(n > 0 and n <= 100);

    /* Determine number of strings in set of rules */
    int numStr = 0;
    // Step through each rule
    YR_RULE* rule = NULL;
    yr_rules_foreach(rules, rule) {
        // Step through each string in the rule
        YR_STRING* string = NULL;
        yr_rule_strings_foreach(rule, string) {
            numStr++;
        }
    }

    // Ensure that at least one signature exists in the file
    assert(numStr > 0);

    /* Add the length of each signature string into a list */
    int lenList[numStr]; 
    int idx = 0;
    // Step through each rule
    yr_rules_foreach(rules, rule) {
        // Step through each string in the rule
        YR_STRING* string = NULL;
        yr_rule_strings_foreach(rule, string) {
            lenList[idx] = string->length;
            idx++;
        }
    }

    /* DEBUG
    printf("CREATED LIST OF LENGTHS:\n{ ");
    for (int i = 0; i < numStr; i++)
        printf("%d ", lenList[i]);
    printf("}\n");
    */

    // Sort the signature lengths in increasing order
    qsort(lenList, numStr, sizeof lenList[0], cmp_int);

    /* DEBUG
    printf("SORTED LIST OF LENGTHS:\n{ ");
    for (int i = 0; i < numStr; i++)
        printf("%d ", lenList[i]);
    printf("}\n");
    */

    // Calculate and return the 90th percentile
    // TODO: allow arbitrary nth percentile, handle edge case of 0th percentile
    double percent = (double)n / 100;
    int nPercentileIdx = ceil(percent * numStr) - 1;
    return lenList[nPercentileIdx];
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
    int yaraCallRet = yr_rules_scan_mem(rules,      // Rule file
                                        scan,       // Buffer to scan
                                        scan_len,   // Buffer length
                                        0,          // Flags
                                        NULL,       // TODO: write callback function
                                        NULL,       // TODO: look into user data
                                        1000);      // Timeout
    return 0;
}

