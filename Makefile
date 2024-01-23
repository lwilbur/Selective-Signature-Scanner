# variables
toolName = 3S
mainName = runTest

.PHONY : clean test 

$(toolName) : $(mainName).c $(toolName).h $(toolName).c 
	gcc $(mainName).c $(toolName).c -o $(toolName)

clean :
	rm -f $(toolName)

test : $(toolName)
	./$(toolName)
	
