# variables
toolName = 3S
mainName = cli
header   = -I/opt/homebrew/Cellar/yara/4.3.2_1/include
libs     = -L/opt/homebrew/Cellar/yara/4.3.2_1/lib -lyara
yaraDir  = yara_test_files
testDir  = yara_test_suite

.PHONY : clean test testSuite

$(toolName) : $(mainName).c $(toolName).h $(toolName).c 
	gcc -Wall -g -o $(toolName) $(mainName).c $(toolName).c $(header) $(libs)

clean :
	rm -rf $(toolName) $(toolName).dSYM

test : $(toolName)
	./$(toolName) $(yaraDir)/testRule.yar $(yaraDir)

testSuite : $(toolName)
	@echo "\nRUNNING TEST RULE ON MATCH DIRECTORY --- ALL FILES SHOULD MATCH"
	./$(toolName) $(testDir)/testSuiteRule.yar $(testDir)/yara_test_suite_match

	@echo "\nRUNNING TEST RULE ON NOMATCH DIRECTORY --- NO FILES SHOULD MATCH"
	./$(toolName) $(testDir)/testSuiteRule.yar $(testDir)/yara_test_suite_nomatch

