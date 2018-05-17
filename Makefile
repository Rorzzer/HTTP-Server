##Adapted from http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
CC=gcc
CFLAGS=-Wall -g -std=gnu99 -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -lssl -lcrypto
DEPS = certcheck.h
OBJ = certcheck.o
EXE = certcheck
## -L/usr/local/lib/openssl/ -I/usr/local/include/openssl
##Create .o files from .c files. Searches for .c files with same .o names given in OBJ
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

##Create executable linked file from object files. 
$(EXE): $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

##Delete object files
clean:
	/bin/rm $(OBJ)

##Performs clean (i.e. delete object files) and deletes executable
clobber: clean
	/bin/rm $(EXE) 
