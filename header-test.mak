CFLAGS =	-ggdb -std=c99 -Wall -Wextra -pedantic
CLIBFLAGS =	-lm

# for testing, link test_keys.o with student mirsa_lib.o

test_keys:  all
	$(CC) $(CFLAGS) test_keys.o $(OBJFILES) $(CLIBFLAGS) -o $@

