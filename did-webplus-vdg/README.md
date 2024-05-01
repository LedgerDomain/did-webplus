# did-webplus-vdg

Basic reference implementation for Verifiable Data Gateway (VDG) service for did:webplus.

## Usage

Ensure you're in the did-webplus-vdg dir.

### Build

This will build the necessary docker images:

    make build

### Run

This will spin up the VDG and subordinate services:

    make run

### Follow VDG logs

This will follow the logs of the already-running VDG:

    make logs

### Single command for dev iteration

This will build and re-deploy the VDG, useful e.g. when developing the VDG and testing the changes:

    make build && make run && make logs

then hit Ctrl+C to abort.  Simply run the command again to rebuild and re-deploy.

### Stopping the services

This will stop the running services:

    make stop

### (Re)Starting the services

This will (re)start the services in the background:

    make start

## Notes

The docker-compose will spin up docker containers for the did-webplus VDG, a PostgreSQL database, and an "autoheal" service which will restart the VDG if it goes down.  The VDG, which inside the docker network will be available at witness.org:80, and that port will be mapped to the host machine to port 8086.  The healthcheck can be done manually via

    curl http://localhost:8086/health

There will be a volume called `did-webplus-postgres_data` that contains the VDG's PostgreSQL database's data.  This volume can be deleted via a `docker volume` subcommand.  See `docker volume --help` for more info.

See other targets in `Makefile` for more functionality:

    make help

### Testing

Optionally run the test(s) against the running VDG via

    RUST_LOG=debug cargo test -p did-webplus-vdg --all-features -- --nocapture
