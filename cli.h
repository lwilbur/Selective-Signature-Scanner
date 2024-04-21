#ifndef _CLI_H
#define _CLI_H

#include <stdio.h>
#include <stdlib.h>

/*
 * @brief Loads directory of rules, runs them on both files, reporting data on
 * runtime and accuracy.
 */
int main(int argc, char* argv[]);

/*
 * @brief Run rules on all files in targetDirToScan, scanning the whole files.
 */
int fullFileTest(DIR* dTarget,
                 char* targetDirToScan,
                 YR_RULES* rules,
                 bool print);

/*
 * @brief Run rules on all files in targetDirToScan, scanning only the head
 * and tail of length headFootLen.
 */
int percentileTest(DIR* dTarget, 
                   char* targetDirToScan,
                   int headFootLen,
                   YR_RULES* rules,
                   bool print);

/*
 * @brief time.h wrapper, starts a timer.
 */
void timerStart();

/*
 * @brief time.h wrapper, returns time elapsed since timer_start in seconds.
 */
double timerEnd();

#endif
