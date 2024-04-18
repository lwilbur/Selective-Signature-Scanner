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

int calcNPercentileLength(YR_RULES* rules, int n);

/*
 * @brief Excises the beginning and end of file, returning it in an array.
 *
 * @param filename
 * @param numChars
 */
char* exciseHeadTail(char filename[], int numChars);

/*
 * @brief Runs Yara on a selected file.
 *
 * Runs Yara on a selected file -- intended for use on a file created by an
 * excise function.
 *
 * @param filename string name of file to be scanned
 * @param yaraFile string name of Yara rule file to be used
 */
bool invokeYaraOnBuffer(char scan[], size_t scan_len, YR_RULES* rules);

bool headTailScan(char filename[], YR_RULES* rules, size_t scan_len);
bool fullScan(char filename[], YR_RULES* rules);

#endif /*_3S_H*/
