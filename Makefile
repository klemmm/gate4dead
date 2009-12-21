LDLIBS="-lgarena"
all: gate4dead

conf.o: conf.c conf.h

gate4dead.o: gate4dead.c conf.h

gate4dead: gate4dead.o conf.o

clean:
	rm -f gate4dead *.o *~ DEADJOE core.*
