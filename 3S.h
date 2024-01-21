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

/*
 * @brief Excises the beginning and end of filename, saving into a new file.
 *
 * Calculates a number of characters, depending of the size of signature, to
 * be cut from the beginning and end a file. Then, loads the file identified
 * by filename, saves those beginning and ending characters into a new file.
 *
 * @param inFilename string name of the file from which portions will be cut
 * @param outFilename string name of the file to which excised portions will
 *                      be output
 * @param signature string containing the signature being searched for
 * @return 0 on success, 1 on error.
 */
int exciseBeginningEnd(char inFilename[], 
                       char outFilename[],
                       char signature[]);

/*
 * @brief Selects sections of a file to search, based on an ML model.
 *
 * Will be implemented once exciseBeginningEnd has been completed and
 * comprehensively tested.
 */
int smartExcise(char filename[]);

/*
 * @brief Runs Yara on a selected file.
 *
 * Runs Yara on a selected file -- intended for use on a file created by an
 * excise function.
 *
 * @param filename string name of file to be scanned
 * @param yaraFile string name of Yara rule file to be used
 */
int invokeYaraOnFile(char filename[], char yaraFile[]);

#endif /*_3S_H*/
