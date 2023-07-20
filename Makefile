# Copyright (c) 2023 NTT Communications Corporation
# Copyright (c) 2023 Takeru Hayasaka

GOCMD=go
BINARY_NAME=fluvia
CLANG ?= clang
CFLAGS :=  -O2 -g -Wall $(CFLAGS)

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

.PHONY: all build clean

all: go-gen build

build:
	mkdir -p out/bin
	$(GOCMD) build -o out/bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)/main.go

clean:
	rm -fr out

go-gen: export BPF_CLANG := $(CLANG)
go-gen: export BPF_CFLAGS := $(CFLAGS)
go-gen:
	go generate ./...

help:
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_0-9-]+:.*?##.*$$/) {printf "    ${YELLOW}%-20s${GREEN}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)
