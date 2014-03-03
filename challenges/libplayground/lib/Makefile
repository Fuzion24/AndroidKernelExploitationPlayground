all: libplayground.so

install: libplayground.so playground.h
	cp playground.h /usr/include/playground.h
	cp libplayground.so /usr/lib/libplayground.so

libplayground.so: libplayground.c playground.h
	gcc libplayground.c -o libplayground.so -fPIC -shared

uninstall:
	rm /usr/lib/libplayground.so
	rm /usr/include/playground.h

clean:
	rm libplayground.so
