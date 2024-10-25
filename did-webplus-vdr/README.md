# did-webplus-vdr

Basic reference implementation for Verifiable Data Registry (VDR) service for did:webplus.

It's certainly possible to build and run a native binary, but for now the functionality is easiest to demonstrate within a docker-compose.  Instructions on building and running the native binary will be added later.

## Building and running the dockerized service(s)

Ensure you're in the did-webplus-vdr dir.

### Build

This will build the necessary docker images:

    make build

### Run

This will spin up the VDR and subordinate services:

    make run

### Follow VDR logs

This will follow the logs of the already-running VDR:

    make logs

Alternately, this will follow the logs of all the services running in the docker-compose:

    make logs-all

### Single command for dev iteration

This will build and re-deploy the VDR, useful e.g. when developing the VDR and testing the changes:

    make build && make run && make logs-all

then hit Ctrl+C to abort.  Simply run the command again to rebuild and re-deploy.

### Stopping the services

This will stop the running services:

    make stop

### (Re)Starting the services

This will (re)start the services in the background:

    make start

### Stopping and removing the services

This will stop and remove the services and the network, though it will leave the volume that the PostgreSQL database is stored on:

    make down

## Notes

The docker-compose will spin up docker containers for the did-webplus VDR, a PostgreSQL database, and an "autoheal" service which will restart the VDR if it goes down.  The VDR, which inside the docker network will be available at fancy.net:80, and that port will be mapped to the host machine to port 8085.  The healthcheck can be done manually via

    curl http://localhost:8085/health

There will be a volume called `did-webplus-vdr_postgres_data` that contains the VDR's PostgreSQL database's data.  This volume can be deleted via a `docker volume` subcommand.  See `docker volume --help` for more info.

See other targets in `Makefile` for more functionality:

    make help

### Testing

Optionally run the test(s) against the running VDG via

    RUST_LOG=debug cargo test -p did-webplus-vdg --all-features -- --nocapture

This will create a couple of DIDs and update with a fresh set of keys several times each.
