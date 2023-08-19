APPNAME=run_tests
CC=gcc
CCFLAGS=-O2 -Wall
FLAGS_INCLUDE=-I/opt/homebrew/include
FLAGS_LIB=-L/opt/homebrew/lib -L../src -lbotje_gcrypt -lcmocka -lgcrypt
OBJECTS_TESTS=tests_botje_gcrypt.o tests.o

all: src tests

clean:
	rm -f $(APPNAME) $(OBJECTS_TESTS)

src:
	$(MAKE) -C ../src

tests_botje_gcrypt.o: tests_botje_gcrypt.c tests_botje_gcrypt.h
	$(CC) $(CCFLAGS) $(FLAGS_INCLUDE) -c -o tests_botje_gcrypt.o tests_botje_gcrypt.c

tests.o: tests.c
	$(CC) $(CCFLAGS) $(FLAGS_INCLUDE) -c -o tests.o tests.c

tests: $(OBJECTS_SHARED) $(OBJECTS_TESTS)
	$(CC) $(CCFLAGS) $(FLAGS_LIB) -o $(APPNAME) $(OBJECTS_TESTS)

run:
	make clean && make && DYLD_LIBRARY_PATH=../src ./run_tests
