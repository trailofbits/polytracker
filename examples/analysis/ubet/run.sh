#/bin/sh

docker build -t ub-test -f Dockerfile.polytracker .
docker run -ti --rm -v $(pwd):/workdir ub-test /usr/bin/python3 eval.py src/ub.cpp $@