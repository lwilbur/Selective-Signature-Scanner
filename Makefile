# variables
toolName = 3S

.PHONY : clean test 

$(toolName) : $(toolName).c
	gcc $(toolName).c -o $(toolName)

clean :
	rm -f $(toolName)

test : $(toolName).out
	
