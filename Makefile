.PHONY: help sqlx-prepare sqlx-prepare-vdr
.DEFAULT_GOAL := help
SHELL = bash

help:
	@echo "Please use 'make <target>' where <target> is one of the following:"
	@echo "  sqlx-prepare          to generate files for SQLX_OFFLINE build for all relevant crates"
	@echo "  sqlx-prepare-vdr      to generate files for SQLX_OFFLINE build for did-webplus-vdr"

#########################################################
# Make rules for generating files for SQLX_OFFLINE builds
#########################################################

# Generate files for SQLX_OFFLINE build for all relevant crates.
sqlx-prepare: sqlx-prepare-vdr

# Generate files for SQLX_OFFLINE build for did-webplus-vdr
sqlx-prepare-vdr:
	cd did-webplus-vdr && cargo sqlx prepare
