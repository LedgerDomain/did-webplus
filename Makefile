.PHONY: deps run start run-background run-foreground up down rm rmi stop logs logs-all lint remove-docker-image reset build rebuild shell docker-build sqlx-prepare sqlx-prepare-vdr
.DEFAULT_GOAL := help
SHELL = bash

export VDR_PROJECT_NAME = did-webplus-vdr
export VDR_CONTAINER_NAME = example.com

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

# TODO: Rename make rules to include "vdr", so that "vdg" and "cli" rules can be made.

# Build necessary container(s) read from Docker Compose
build:
	@echo "\---- Performing docker build ... -----"
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml build

# Docker build bypassing
docker-build:
	DOCKER_BUILDKIT=1 docker build --platform=linux/amd64 -f did-webplus-vdr/Dockerfile -t $(VDR_PROJECT_NAME):latest .

# Notes: To remove cache add --no-cache
#        To see progress add --progress plain

# This is our default logic for "make run" or "make start", to use the backgrounded
run:
    # TODO
	@echo -e "\n----- Starting docker-compose -----"
	@$(MAKE) run-background
	@echo -e "\n----- Tailing logs -----"
	@$(MAKE) logs

# Start is an alias for run (above)
start: run

# This will run a dev-friendly (backgrounded) version of our app in dev mode
# NOTE: This will not deploy stepCI and workflows will not run
run-background: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml up -d

# This will run a dev-friendly (foregrounded) version of our app in dev mode
# NOTE: This will not deploy stepCI and workflows will not run
run-foreground: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml up

# Remove our containers from docker compose
rm: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml rm

# Bring up the docker-compose
up: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml up

# Take down the docker-compose
down: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml down

# This is to stop
stop: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml stop

# This will view the logs of ONLY our application, easier for devs
logs: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml logs -f --tail=100 $(VDR_CONTAINER_NAME)

# This will view the logs for ALL containers, for a sysadmin/devops or when needed
logs-all: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml logs -f --tail=100

# Please someone make me work?
lint:
	cargo clippy

# Remove docker image
remove-docker-image: deps stop rm
	docker rmi $(VDR_PROJECT_NAME) || true

rmi: remove-docker-image

# This will completely reset and rebuild, use this as a last resort incase it stops working
reset: deps
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml down || true
	$(DOCKER_COMPOSE_COMMAND) -f did-webplus-vdr/docker-compose.yml rm -f -s -v || true
	$(MAKE) remove-docker-image

# This will completely rebuild the docker image without resetting
rebuild: remove-docker-image build

# This will shell you into the running container
shell:
	docker exec -ti $(VDR_PROJECT_NAME)_$(VDR_CONTAINER_NAME)_1 bash

#########################################################
# Make rules for generating files for SQLX_OFFLINE builds
#########################################################

# Generate files for SQLX_OFFLINE build for all relevant crates.
sqlx-prepare: sqlx-prepare-vdr

# Generate files for SQLX_OFFLINE build for did-webplus-vdr
sqlx-prepare-vdr:
	cd did-webplus-vdr && cargo sqlx prepare
