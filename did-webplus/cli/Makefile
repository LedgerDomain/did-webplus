.PHONY: remove-docker-image rmi shell docker-build
.DEFAULT_GOAL := help
SHELL = bash

export CLI_PROJECT_NAME = did-webplus-cli

help:
	@echo "Please use 'make <target>' where <target> is one of the following:"
	@echo "  docker-build          to build the docker image bypassing docker-compose"
	@echo "  remove-docker-image   to remove docker image"
	@echo "  rmi                   to remove docker image"
	@echo "  shell                 to shell you into the running container"

# Docker build bypassing
docker-build:
	DOCKER_BUILDKIT=1 docker build --platform=linux/amd64 -t $(CLI_PROJECT_NAME):latest -f ./Dockerfile ../..

# Remove docker image
remove-docker-image: deps stop rm
	docker rmi $(CLI_PROJECT_NAME) || true

# Alias for remove-docker-image
rmi: remove-docker-image

# This will shell you into the CLI container that is connected to an already-running VDG
# docker-compose network.  See did-webplus-vdg/Makefile for details on how to run that.
#
# This make target mounts the host dir ~/.did-webplus to the container's /root/.did-webplus dir,
# and sets several env vars to point to the VDG, and make it very convenient to shell in and
# run the `did-webplus` binary manually against the VDG and VDR.
#
# Note that because TLS is not being used currently in the VDG/VDR, the env var
# DID_WEBPLUS_HTTP_SCHEME_OVERRIDE (development-only) is used to use "http" scheme for those
# connections, instead of the default "https" scheme.
shell:
	mkdir -p ~/.did-webplus.docker
	docker run --rm --tty --interactive \
		--network vdg_default \
		--volume ~/.did-webplus.docker:/root/.did-webplus \
		--env RUST_BACKTRACE=1 \
		--env RUST_LOG=error \
		--env DID_WEBPLUS_VDG=witness.org \
		--env DID_WEBPLUS_VDR=http://fancy.net \
		--env DID_WEBPLUS_HTTP_SCHEME_OVERRIDE=fancy.net=http \
		--entrypoint bash \
		$(CLI_PROJECT_NAME):latest
