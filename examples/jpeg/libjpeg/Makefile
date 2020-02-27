.phony: all
all: example_libjpeg

jpeg-9c:
	wget https://www.ijg.org/files/jpegsrc.v9c.tar.gz
	tar -xzvf jpegsrc.v9c.tar.gz
	rm jpegsrc.v9c.tar.gz

jpeg-9c/Makefile: jpeg-9c
	cd jpeg-9c && touch .PLACEHOLDER && POLYPATH=.PLACEHOLDER CFLAGS="-O0" ./configure --disable-shared --enable-static --prefix=$(CURDIR)/jpeg-9c/ && rm .PLACEHOLDER

jpeg-9c/lib/libjpeg.a jpeg-9c/include/jpeglib.h: jpeg-9c/Makefile
	cd jpeg-9c && make -j$(nproc) install

example_libjpeg.o : example_libjpeg.c jpeg-9c/include/jpeglib.h
	$(CC) -Ijpeg-9c/include -O0 -c $< -o $@

example_libjpeg : example_libjpeg.o jpeg-9c/lib/libjpeg.a
	$(CC) -O0 $^ -o $@

.phony: clean
clean:
	rm -rf jpeg-9c example_libjpeg example_libjpeg.o
