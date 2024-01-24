/** @file 3S.h
 *  @brief Function prototypes for the Selective Signature Scanner.
 *
 *  Contains prototypes for the main functions required by the selective
 *  signature scanner. 
 */

#ifndef _3S_H
#define _3S_H

#include <stdio.h>
#include <stdlib.h>

int calc90PercentileLength(char rule_database[]);

/*
 * @brief Excises the beginning and end of file, returning it in an array.
 *
 * @param filename
 * @param numChars
 */
char* exciseHeadTail(char filename[], int numChars);

/*
 * @brief Selects sections of a file to search, based on an ML model.
 *
 * Will be implemented once exciseBeginningEnd has been completed and
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

#endif /*_3S_H*/
