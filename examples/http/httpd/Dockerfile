FROM trailofbits/polytracker:latest
LABEL org.opencontainers.image.authors="lisa.overall@trailofbits.com"

RUN rm -rf /polytracker/examples/http/httpd && mkdir -p /polytracker/examples/http/httpd

WORKDIR /polytracker/examples/http/httpd
RUN git clone --branch 2.4.13 https://github.com/apache/httpd.git
RUN apt update && apt install -y netcat curl autoconf libtool-bin && rm -rf /var/lib/apt/lists/*

WORKDIR /polytracker/examples/http/httpd/httpd
RUN mkdir -p srclib/apr srclib/apr-util srclib/pcre srclib/expat
RUN curl https://archive.apache.org/dist/apr/apr-1.7.0.tar.gz -o apr-1.7.0.tar.gz \
    && tar xfz apr-1.7.0.tar.gz -C srclib/apr --strip-components 1 \
    && rm apr-1.7.0.tar.gz
RUN curl https://archive.apache.org/dist/apr/apr-util-1.6.1.tar.gz -o apr-util-1.6.1.tar.gz \
    && tar xfz apr-util-1.6.1.tar.gz -C srclib/apr-util --strip-components 1 \
    && rm apr-util-1.6.1.tar.gz
RUN curl -L https://sourceforge.net/projects/pcre/files/pcre/8.39/pcre-8.39.tar.gz/download -o pcre-8.39.tar.gz \
    && tar xfz pcre-8.39.tar.gz -C srclib/pcre --strip-components 1 \
    && rm pcre-8.39.tar.gz
RUN curl -L https://github.com/libexpat/libexpat/releases/download/R_2_4_7/expat-2.4.7.tar.gz -o expat-2.4.7.tar.gz \
    && tar xfz expat-2.4.7.tar.gz -C srclib/expat --strip-components 1 \
    && rm expat-2.4.7.tar.gz

WORKDIR /polytracker/examples/http/httpd/httpd/srclib/pcre
RUN polytracker build ./configure --disable-shared
RUN polytracker build make

WORKDIR /polytracker/examples/http/httpd/httpd/srclib/expat
RUN polytracker build ./configure --disable-shared
RUN polytracker build make

# apr, apr-util are configured via httpd's configure script

WORKDIR /polytracker/examples/http/httpd/httpd
RUN polytracker build ./buildconf
RUN CFLAGS="-I$(pwd)/srclib/pcre -I$(pwd)/srclib/expat/lib" \
    LDFLAGS="-L$(pwd)/srclib/pcre/.libs -L$(pwd)/srclib/expat/lib/.libs" \
    polytracker build ./configure --disable-shared --with-mpm=prefork --with-pcre=srclib/pcre/pcre-config --with-included-apr \
    --enable-mods-static='authz_core unixd'
RUN CFLAGS="-I$(pwd)/srclib/pcre -I$(pwd)/srclib/expat/lib" \
    LDFLAGS="-L$(pwd)/srclib/pcre/.libs -L$(pwd)/srclib/expat/lib/.libs" \
    polytracker build make -j$((`nproc`+1))

RUN polytracker instrument-targets --taint --cflog httpd
RUN mv httpd.instrumented httpd_track
# overwrite binary to be installed with our polytracker-instrumented version
RUN cp httpd_track httpd
RUN polytracker build make install

COPY harness_httpd.sh /polytracker/examples/http/httpd/
COPY httpd.conf /usr/local/apache2/conf/

# Note, the /workdir and /testcase directories are intended to be mounted at runtime
VOLUME ["/workdir", "/testcase"]
WORKDIR /workdir
