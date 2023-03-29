.phony: all
all: example_picohttpparser

picohttpparser:
	git clone https://github.com/h2o/picohttpparser.git

picohttpparser/picohttpparser.a picohttpparser/picohttpparser.h: picohttpparser
	cd picohttpparser && gcc -c picohttpparser.c && ar -rc picohttpparser.a picohttpparser.o

example_picohttpparser.o : example_picohttpparser.c picohttpparser/picohttpparser.h
	$(CC) -Ipicohttpparser -O0 -c $< -o $@

example_picohttpparser : example_picohttpparser.o picohttpparser/picohttpparser.a
	$(CC) -O0 $^ -o $@

.phony: clean
clean:
	rm -rf picohttpparser example_picohttpparser example_picohttpparser.o