.PHONY: help sqlx-prepare sqlx-prepare-doc-storage-postgres sqlx-prepare-doc-storage-sqlite sqlx-prepare-vdg sqlx-prepare-vdr sqlx-prepare-wallet-storage-sqlite
.DEFAULT_GOAL := help
SHELL = bash

help:
	@echo "Please use 'make <target>' where <target> is one of the following:"
	@echo "  sqlx-prepare          				to generate files for SQLX_OFFLINE build for all relevant crates"
	@echo "  sqlx-prepare-doc-storage-postgres  to generate files for SQLX_OFFLINE build for did-webplus-doc-storage-postgres"
	@echo "  sqlx-prepare-doc-storage-sqlite    to generate files for SQLX_OFFLINE build for did-webplus-doc-storage-sqlite"
	@echo "  sqlx-prepare-vdg      				to generate files for SQLX_OFFLINE build for did-webplus-vdg"
	@echo "  sqlx-prepare-vdr      				to generate files for SQLX_OFFLINE build for did-webplus-vdr"
	@echo "  sqlx-prepare-wallet-storage-sqlite to generate files for SQLX_OFFLINE build for did-webplus-wallet-storage-sqlite"

#########################################################
# Make rules for generating files for SQLX_OFFLINE builds
#########################################################

# Generate files for SQLX_OFFLINE build for all relevant crates.
sqlx-prepare: sqlx-prepare-doc-storage-postgres sqlx-prepare-doc-storage-sqlite sqlx-prepare-vdg sqlx-prepare-vdr sqlx-prepare-wallet-storage-sqlite

# Generate files for SQLX_OFFLINE build for did-webplus-doc-storage-postgres
sqlx-prepare-doc-storage-postgres:
	cd did-webplus-doc-storage-postgres && cargo sqlx prepare

# Generate files for SQLX_OFFLINE build for did-webplus-doc-storage-sqlite
sqlx-prepare-doc-storage-sqlite:
	cd did-webplus-doc-storage-sqlite && cargo sqlx prepare

# Generate files for SQLX_OFFLINE build for did-webplus-vdg
sqlx-prepare-vdg:
	cd did-webplus-vdg && cargo sqlx prepare

# Generate files for SQLX_OFFLINE build for did-webplus-vdr
sqlx-prepare-vdr:
	cd did-webplus-vdr && cargo sqlx prepare

# Generate files for SQLX_OFFLINE build for did-webplus-wallet-storage-sqlite
sqlx-prepare-wallet-storage-sqlite:
	cd did-webplus-wallet-storage-sqlite && cargo sqlx prepare

