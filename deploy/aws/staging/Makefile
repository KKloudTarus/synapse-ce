SHELL := /usr/bin/env bash

.PHONY: fmt validate test

fmt:
	terraform fmt -recursive

validate:
	terraform init -backend=false -input=false
	terraform validate

test:
	./scripts/test.sh
