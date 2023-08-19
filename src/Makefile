CC=gcc

all: botje_gcrypt.o libbotje_gcrypt.so

clean:
	rm -f botje_gcrypt.o libbotje_gcrypt.so

install:
	cp botje_gcrypt.h /opt/homebrew/include/botje_gcrypt.h
	cp libbotje_gcrypt.so /opt/homebrew/lib/libbotje_gcrypt.so

uninstall:
	rm -f /opt/homebrew/include/botje_gcrypt.h
	rm -f /opt/homebrew/lib/libbotje_gcrypt.so

botje_gcrypt.o: botje_gcrypt.c botje_gcrypt.h
	$(CC) -O2 -Wall -I/opt/homebrew/include -c -o botje_gcrypt.o botje_gcrypt.c

libbotje_gcrypt.so: botje_gcrypt.o
	$(CC) -O2 -Wall -L/opt/homebrew/lib -lgcrypt -shared -o libbotje_gcrypt.so botje_gcrypt.o
