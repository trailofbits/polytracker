.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: docker
docker:
	DOCKER_BUILDKIT=1 docker build -t trailofbits/polytracker -f Dockerfile .

.PHONY: lint
lint:
	trunk check

.PHONY: format
format:
	trunk fmt

.PHONY: test
test:
	docker run --rm trailofbits/polytracker pytest /polytracker/tests

.PHONY: clean
clean:
	docker rmi $(docker images --filter=reference="trailofbits/polytracker*" -q)