#ifndef _CLI_H
#define _CLI_H

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]);
int percentileTest(DIR* dTarget, 
                   char* targetDirToScan,
                   int headFootLen,
                   YR_RULES* rules,
                   bool print);

#endif
