#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int calc90PercentileLength(char rule_database[]) {
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
 * @brief Runs Yara on a selected file.
 *
 * Runs Yara on a selected file -- intended for use on a file created by an
 * excise function.
 *
 * @param filename string name of file to be scanned
 * @param yaraFile string name of Yara rule file to be used
 */
int invokeYaraOnFile(char scan[], char yaraFilename[]);

