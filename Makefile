# variables
toolName = 3S
mainName = cli
header   = -I/opt/homebrew/Cellar/yara/4.3.2_1/include
libs     = -L/opt/homebrew/Cellar/yara/4.3.2_1/lib -lyara
yaraDir  = yara_test_files

.PHONY : clean test 

$(toolName) : $(mainName).c $(toolName).h $(toolName).c 
	gcc -Wall -g -o $(toolName) $(mainName).c $(toolName).c $(header) $(libs)

clean :
	rm -rf $(toolName) $(toolName).dSYM

test : $(toolName)
	./$(toolName) $(yaraDir)/MALW_Furtim.yar targetDirectory

test2 : $(toolName)
	./$(toolName) $(yaraDir)/testRule.yar $(yaraDir)/testRuleTarget.txt
