# Create a separate image with the latest source
FROM trailofbits/polytracker:latest
LABEL org.opencontainers.image.authors="lisa.overall@trailofbits.com"

RUN rm -rf /polytracker/examples/http/httpd && mkdir -p /polytracker/examples/http/httpd

WORKDIR /polytracker/examples/http/httpd
RUN git clone --branch 2.4.13 https://github.com/apache/httpd.git
RUN apt update && apt install -y curl autoconf libtool-bin && rm -rf /var/lib/apt/lists/*
# libapr1-dev libaprutil1-dev libpcre3-dev

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
# NOTE: no longer needed after --disable-shared
RUN polytracker extract-bc -o ../../libpcre.bc .libs/libpcre.a

WORKDIR /polytracker/examples/http/httpd/httpd/srclib/expat
RUN polytracker build ./configure --disable-shared
RUN polytracker build make
# NOTE: no longer needed after --disable-shared
RUN polytracker extract-bc -o ../../libexpat.bc  lib/.libs/libexpat.a

# apr, apr-util are configured via httpd's configure script

WORKDIR /polytracker/examples/http/httpd/httpd
RUN polytracker build ./buildconf 
# NOTE: CFLAGS reported unused during instrumentation
RUN CFLAGS="-I$(pwd)/srclib/pcre -I$(pwd)/srclib/expat/lib" \
LDFLAGS="-L$(pwd)/srclib/pcre/.libs -L$(pwd)/srclib/expat/lib/.libs" \
    polytracker build ./configure --disable-shared --with-mpm=prefork --with-pcre=srclib/pcre/pcre-config --with-included-apr
# NOTE: CFLAGS reported unused during instrumentation 
RUN CFLAGS="-I$(pwd)/srclib/pcre -I$(pwd)/srclib/expat/lib" \
LDFLAGS="-L$(pwd)/srclib/pcre/.libs -L$(pwd)/srclib/expat/lib/.libs" \ 
    polytracker build make -j$((`nproc`+1))

# NOTE: no longer needed after configuring dependencies with --disable-shared
# RUN polytracker extract-bc -o httpd.bc httpd
# RUN llvm-link -o httpd-linked.bc httpd.bc libpcre.bc libexpat.bc
# RUN polytracker instrument-bc --taint --ftrace httpd-linked.bc -o instrumented.bc

# TODO: fails here due to undefined references to getrandom()
RUN polytracker instrument-targets --taint --ftrace httpd

# NOTE: no longer needed after configuring dependencies with --disable-shared
# RUN polytracker lower-bc instrumented.bc -t httpd -o httpd.instrumented

RUN mv httpd.instrumented httpd_track

COPY harness_httpd.sh /polytracker/examples/http/httpd/

# Note, the /workdir directory is intended to be mounted at runtime
VOLUME ["/workdir"]
#WORKDIR /workdir
