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
 * Calculate the number of characters in the n-th percentile longest rule in
 * a YR_RULES instance. The 'length' of a rule is the sum of the lengths of 
 * all the strings considered by the rule.
 *
 * @return the 90th percentile length on success, -1 on error
 */
int calcNPercentileLength(YR_RULES* rules, int n) {
    assert(rules != NULL);
    assert(n > 0 && n <= 100);

    // Determine number of rules, ensure at least one rule is in the file 
    int numRules = rules->num_rules;
    assert(numRules > 0);

    // Sum the lengths of each rule's strings and store them in a list 
    int* lenList = calloc(numRules, sizeof(int));
    for (int ruleIdx = 0; ruleIdx < numRules; ruleIdx++) {
        int numStrings = rules->rules_table[ruleIdx].num_atoms;
        for (int stringIdx = 0; stringIdx < numStrings; stringIdx++) {
            lenList[ruleIdx] += rules->rules_table[ruleIdx].strings[stringIdx].length;
        }
    }

    // Sort the signature lengths in increasing order
    qsort(lenList, numRules, sizeof(lenList[0]), cmp_int);

    /* DEBUG
    printf("SORTED LIST OF LENGTHS:\n{ ");
    for (int i = 0; i < numRules; i++)
        printf("%d ", lenList[i]);
    printf("}\n");
    */

    // Calculate and return the 90th percentile
    double percent = (double)n / 100;
    int nPercentileIdx = ceil(percent * numRules) - 1;
    int numChars = lenList[nPercentileIdx];
    free(lenList);
    return numChars;
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

    // Confirm that file is long enough to accomodate header and footer, and
    // resize header/footer to be the length of the file at most (accepting
    // that there will be overlap in the center)
    fseek(file, 0, SEEK_END);
    long byteNum = ftell(file);
    if (byteNum < numChars) {
        numChars = byteNum - 1;
    }

    // Allocate memory for the characters
    char* headTail = malloc(numChars * 2 + 2);  // +1 for \0, +1 for \n at EOF
    assert(headTail != NULL);
    
    // Read the first n characters
    fseek(file, 0, SEEK_SET);
    fread(headTail, 1, numChars, file);

    // Read the last n characters, appending to those already in array
    // NB: for text files, newline will be read, so additional char read at end
    fseek(file, -(numChars + 1), SEEK_END);
    fread(&headTail[numChars], 1, numChars + 1, file);
    headTail[2 * numChars] = '\0';

    // DEBUG 
    // printf("%d head/tail characters: %s\n", numChars, headTail);
    
    // Close file and exit
    fclose(file);
    return headTail;
}


/*
 * @brief Callback used by yr_rules_scan_xxxx functions
 *
 * Updates user_data matchFound to true if a match is found.
 */
int scan_callback(YR_SCAN_CONTEXT* context,
                         int message,
                         void* message_data,
                         void* user_data) {
    // Avoid unused warnings
    (void)context;
    (void)message_data;

    // use user_data to track if a match if found
    if (message == CALLBACK_MSG_RULE_MATCHING)
        *((bool*)user_data) = true;

    return CALLBACK_CONTINUE;
}


/*
 * @brief Runs Yara on a selected buffer.
 *
 * Runs Yara on a selected buffer -- intended for use on a buffer created by an
 * excise function.
 *
 * @param scan buffer to be scanned
 * @param scanLen length of buffer to be scanned
 * @param rules YR_RULES* for the group of rules to apply to buffer
 * @return 1 if match, 0 if no match
 */
bool invokeYaraOnBuffer(char scan[], size_t buffLen, YR_RULES* rules) {
    // scan the given buffer
    bool matchFound = false;
    yr_rules_scan_mem(rules,                  // Rule file
                      (uint8_t*)scan,         // Buffer to scan
                      buffLen,                // Buffer length
                      0,                      // Flags
                      scan_callback,          // callback -- fxn called by scan
                      &matchFound,            // user data
                      1000);                  // Timeout

    // If matchFound has been updated to true, a match was made in scan
    if (matchFound) return true;
    return false;
}


/*
 * @brief Scan only the head and tail of file filename
 */
bool headTailScan(char filename[], YR_RULES* rules, size_t scanLen) {
    char* scanBuffer = exciseHeadTail(filename, scanLen);
    bool match = invokeYaraOnBuffer(scanBuffer, scanLen*2+1, rules);
    free(scanBuffer);
    return match;
}


/*
 * @brief Scan the entire file filename into a buffer in memory.
 *
 * Trust callee to free the buffer.
 */
char* readFullFile(char filename[], long* len) {
    // Load file as binary
    FILE* file = fopen(filename, "rb");
    assert(file != NULL);

    // Get length of file
    fseek(file, 0, SEEK_END);
    long numBytes = ftell(file);
    *(len) = numBytes;

    // Return to start of file, allocate space for file
    fseek(file, 0, SEEK_SET);
    char* contents = malloc(numBytes + 1);  // +1 for \0
    assert(contents != NULL);

    // Save into buffer
    fread(contents, numBytes, 1, file);
    fclose(file);

    // Null-terminate and return
    contents[numBytes] = '\0';
    return contents;
}



bool fullScan(char filename[], YR_RULES* rules) {
    long numBytes = 0;
    char* scanBuffer = readFullFile(filename, &numBytes);
    bool match = invokeYaraOnBuffer(scanBuffer, numBytes, rules);
    free(scanBuffer);
    return match;

    /*
    bool matchFound = false;
    yr_rules_scan_file(rules,                 // Rule file
                       filename,              // name of file to scan
                       0,                     // Flags
                       scan_callback,         // callback -- fxn called by scan
                       &matchFound,           // user data
                       1000);                 // Timeout
    // If matchFound has been updated to true, a match was made in scan
    if (matchFound) return true;
    return false;
    */
}

