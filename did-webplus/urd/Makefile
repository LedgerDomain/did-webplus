.PHONY: deps build run logs logs-all up down start stop rm remove-docker-image rmi reset rebuild shell docker-build
.DEFAULT_GOAL := help
SHELL = bash

export VDG_PROJECT_NAME = did-webplus-urd
export VDG_CONTAINER_NAME = dockerized.urd.local

help:
	@echo "Please use 'make <target>' where <target> is one of the following:"
	@echo "  deps                  to check if docker-compose is installed"
	@echo "  build                 to build the necessary container(s) read from Docker Compose"
	@echo "  docker-build          to build the docker image bypassing docker-compose"
	@echo "  run                   to run app (and subordinate services) in the background"
	@echo "  logs                  to view the logs of ONLY this application, easier for devs"
	@echo "  logs-all              to view the logs for ALL containers, for a sysadmin/devops or when needed"
	@echo "  up                    to bring up the docker-compose"
	@echo "  down                  to take down the docker-compose"
	@echo "  start                 to start the services"
	@echo "  stop                  to stop the services"
	@echo "  rm                    to remove our containers from docker compose"
	@echo "  remove-docker-image   to remove docker image"
	@echo "  rmi                   to remove docker image"
	@echo "  reset                 to completely reset and rebuild, use this as a last resort incase it stops working"
	@echo "  rebuild               to completely rebuild the docker image without resetting"
	@echo "  shell                 to shell you into the running container"

DOCKER_COMPOSE_COMMAND := $(shell docker-compose version > /dev/null 2>&1; \
	if [ $$? -eq 0 ]; then \
		echo "DOCKER_BUILDKIT=1 COMPOSE_COMPATIBILITY=true docker-compose"; \
	else \
		docker compose version > /dev/null 2>&1; \
		if [ $$? -eq 0 ]; then \
		echo "DOCKER_BUILDKIT=1 COMPOSE_COMPATIBILITY=true docker compose"; \
		fi; \
	fi;)

deps:
ifndef DOCKER_COMPOSE_COMMAND
	@echo "Docker compose not found. Please install either docker-compose (the tool) or the docker compose plugin."
	exit 1
endif

# Build necessary container(s) read from Docker Compose
build:
	@echo "\---- Performing docker build ... -----"
	$(DOCKER_COMPOSE_COMMAND) build

# Docker build bypassing
docker-build:
	DOCKER_BUILDKIT=1 docker build --platform=linux/amd64 -t $(VDG_PROJECT_NAME):latest -f ./Dockerfile ../..

# Notes: To remove cache add --no-cache
#        To see progress add --progress plain

# This will run app (and subordinate services) in the background
run: deps
	$(DOCKER_COMPOSE_COMMAND) up -d

# This will view the logs of ONLY this application, easier for devs
logs: deps
	$(DOCKER_COMPOSE_COMMAND) logs -f --tail=100 $(VDG_CONTAINER_NAME)

# This will view the logs for ALL containers, for a sysadmin/devops or when needed
logs-all: deps
	$(DOCKER_COMPOSE_COMMAND) logs -f --tail=100

# Bring up the docker-compose
up: deps
	$(DOCKER_COMPOSE_COMMAND) up

# Take down the docker-compose
down: deps
	$(DOCKER_COMPOSE_COMMAND) down

# This is to start the services
start: deps
	$(DOCKER_COMPOSE_COMMAND) start

# This is to stop the services
stop: deps
	$(DOCKER_COMPOSE_COMMAND) stop

# Remove our containers from docker compose
rm: deps
	$(DOCKER_COMPOSE_COMMAND) rm

# Remove docker image
remove-docker-image: deps stop rm
	docker rmi $(VDG_PROJECT_NAME) || true

# Alias for remove-docker-image
rmi: remove-docker-image

# This will completely reset and rebuild, use this as a last resort incase it stops working
reset: deps
	$(DOCKER_COMPOSE_COMMAND) down || true
	$(DOCKER_COMPOSE_COMMAND) rm -f -s -v || true
	$(MAKE) remove-docker-image

# This will completely rebuild the docker image without resetting
rebuild: remove-docker-image build

# This will shell you into the running container
shell:
	docker exec -ti $(VDG_PROJECT_NAME)_$(VDG_CONTAINER_NAME)_1 bash

dev:
	make build run logs