#include <stdio.h>
#include <stdlib.h>

int exciseBeginningEnd(char inFilename[], 
                       char outFilename[],
                       char signature[]);

int smartExcise(char filename[]);

int invokeYaraOnFile(char filename[], char yaraFile[]);
