# variables
toolName = 3S
mainName = cli
header   = -I/opt/homebrew/Cellar/yara/4.5.0/include
libs     = -L/opt/homebrew/Cellar/yara/4.5.0/lib -lyara
yaraDir  = yara_test_files
testDir  = yara_test_suite

.PHONY : clean test testSuite

$(toolName) : $(mainName).h $(mainName).c $(toolName).h $(toolName).c
	gcc -Wall -g -o $(toolName) $(mainName).c $(toolName).c $(header) $(libs)

clean :
	rm -rf $(toolName) $(toolName).dSYM


test: $(toolName)
	@echo "\nRUNNING TEST RULES ON MATCH DIRECTORY --- ALL FILES SHOULD MATCH"
	./$(toolName) $(testDir)/rules $(testDir)/match

	@echo "\nRUNNING TEST RULES ON NOMATCH DIRECTORY --- NO FILES SHOULD MATCH"
	./$(toolName) $(testDir)/rules $(testDir)/nomatch

