PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

# Оболочка контроллера часто экспортирует mitogen_linear. Playbook'и Molecule
# его не содержат, поэтому тесты и lint идут на встроенной стратегии.
export ANSIBLE_STRATEGY := linear
unexport ANSIBLE_STRATEGY_PLUGINS

# Docker Desktop на macOS слушает ~/.docker/run/docker.sock, а не /var/run/docker.sock.
ifeq ($(DOCKER_HOST),)
ifneq ($(wildcard $(HOME)/.docker/run/docker.sock),)
export DOCKER_HOST := unix://$(HOME)/.docker/run/docker.sock
endif
endif

IMAGE ?= host-audit-ubuntu2404:local

.PHONY: unit lint test test-vulnerable test-hardened link image

$(BIN)/molecule: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install -U pip
	$(BIN)/python -m pip install -r requirements.txt

unit:
	$(PYTHON) -m unittest discover -s tests -v

lint: $(BIN)/molecule
	$(BIN)/ansible-lint
	$(BIN)/yamllint .

test-vulnerable: $(BIN)/molecule image
	$(BIN)/molecule test -s vulnerable

test-hardened: $(BIN)/molecule image
	$(BIN)/molecule test -s hardened

test: unit test-vulnerable test-hardened

link:
	mkdir -p .cache/roles
	ln -sfn "$(CURDIR)" .cache/roles/host_audit

image:
	docker build -t $(IMAGE) -f molecule/Dockerfile molecule
