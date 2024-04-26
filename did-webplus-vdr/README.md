# did-webplus-vdr

Basic reference implementation for Verifiable Data Registry (VDR) service for did:webplus.

## Usage

From the did-webplus repo root dir:
-   Build the docker-compose images via `make build`
-   Run the docker-compose services either:
    -   in the foreground via `make run-foreground` or
    -   in the background via `make run-background` (or equivalently `make run`).
    This will spin up docker containers for the did-webplus VDR, a PostgreSQL database, and an "autoheal" service which will restart the VDR if it goes down.  The VDR, which inside the docker network will be available at example.com:80, and that port will be mapped to the host machine to port 8085.  The healthcheck can be done manually via

        curl http://localhost:8085/health

    There will be a volume called `did-webplus-vdr_postgres_data` that contains the PostgreSQL service's data.
-   Optionally run the test(s) against the running VDR via

        RUST_LOG=debug cargo test -p did-webplus-vdr --all-features -- --nocapture

    This will create a DID and update it with a fresh set of keys several times.
-   Stop and remove the containers via `make down`
-   The PostgreSQL service's data can be deleted via a `docker volume` subcommand.  See `docker volume --help` for more info.
-   See other targets in `Makefile` for more functionality.
