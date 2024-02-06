#include "yara.h"
#include "3S.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>


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
    assert(n > 0 && n <= 100);

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
    char* headTail = malloc(numChars * 2 + 2);  // +1 for \0, +1 for \n at EOF
    assert(headTail != NULL);
    
    // Read the first n characters
    // TODO handle file length <= 2*numChars
    fseek(file, 0, SEEK_SET);
    fread(headTail, 1, numChars, file);

    // Read the last n characters, appending to those already in array
    // NB: for text files, newline will be read, so additional char read at end
    fseek(file, -(numChars + 1), SEEK_END);
    fread(&headTail[numChars], 1, numChars + 1, file);
    headTail[2 * numChars] = '\0';

    // DEBUG 
    // printf("%d head/tail characters: %s\n", numChars, headTail);

    return headTail;
}


/*
 * @brief Selects sections of a file to search, based on an ML model.
 *
 * Will be implemented once exciseHeadTail has been completed and
 * comprehensively tested.
 */
int smartExcise();


int buffer_scan_callback(YR_SCAN_CONTEXT* context,
                         int message,
                         void* message_data,
                         void* user_data) {

    // use user_data to track if a match if found
    if (message == CALLBACK_MSG_RULE_MATCHING)
        *((int*)user_data) = true;

    return CALLBACK_CONTINUE;
}


/*
 * @brief Runs Yara on a selected buffer.
 *
 * Runs Yara on a selected file -- intended for use on a file created by an
 * excise function.
 *
 * @param filename string name of file to be scanned
 * @param yaraFile string name of Yara rule file to be used
 * @return 1 if match, 0 if no match
 */
bool invokeYaraOnBuffer(char scan[], size_t scanLen, YR_RULES* rules) {
    // scan the given buffer
    bool matchFound = false;
    yr_rules_scan_mem(rules,                  // Rule file
                      (uint8_t*)scan,         // Buffer to scan
                      scanLen * 2 + 1,        // Buffer length
                      0,                      // Flags
                      buffer_scan_callback,   // callback -- fxn called by scan
                      &matchFound,            // user data -- true if match
                      1000);                  // Timeout

    // If matchFound has been updated to true, a match was made in scan
    if (matchFound) return true;
    return false;
}


bool headTailScan(char filename[], YR_RULES* rules, size_t scanLen) {
    char* scanBuffer = exciseHeadTail(filename, scanLen);
    bool matchFound = invokeYaraOnBuffer(scanBuffer, scanLen, rules);
    return matchFound;
}

