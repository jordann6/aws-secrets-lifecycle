SHELL := /bin/bash
REGION := us-east-1
TF := terraform -chdir=terraform
PY := python3

.PHONY: build test deploy seed traffic scan report rotate destroy clean

# Dry-run the rotation executor against one secret. Requires SECRET_ARN and
# SCAN_ID; set APPROVE=1 to actually rotate (secret must carry the
# secops:rotation-approved=true tag). Example:
#   make rotate SECRET_ARN=arn:...:secret:secops-demo/token SCAN_ID=2026-...
rotate:
	@test -n "$(SECRET_ARN)" || { echo "set SECRET_ARN=..."; exit 1; }
	@test -n "$(SCAN_ID)" || { echo "set SCAN_ID=..."; exit 1; }
	aws lambda invoke --function-name secops-executor \
		--cli-read-timeout 150 --cli-binary-format raw-in-base64-out \
		--payload '{"secret_arn":"$(SECRET_ARN)","scan_id":"$(SCAN_ID)","approve":true,"dry_run":$(if $(APPROVE),false,true)}' \
		/tmp/executor-out.json > /dev/null
	@cat /tmp/executor-out.json | $(PY) -m json.tool

build:
	cd scanner && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
		go build -ldflags='-s -w' -o build/bootstrap ./cmd/scanner
	cd scanner/build && zip -q -j scanner.zip bootstrap
	rm -rf analyzer/build && mkdir -p analyzer/build/pkg
	$(PY) -m pip -q install --target analyzer/build/pkg \
		--platform manylinux2014_aarch64 --python-version 3.12 \
		--only-binary=:all: anthropic pyyaml
	cp analyzer/src/*.py config/control-mappings.yaml analyzer/build/pkg/
	cd analyzer/build/pkg && zip -q -r ../analyzer.zip .
	rm -rf reporter/build && mkdir -p reporter/build/pkg
	cp reporter/src/*.py reporter/build/pkg/
	cd reporter/build/pkg && zip -q -r ../reporter.zip .
	rm -rf executor/build && mkdir -p executor/build/pkg
	cp executor/src/*.py executor/build/pkg/
	cd executor/build/pkg && zip -q -r ../executor.zip .

test:
	cd scanner && go vet ./... && go test ./...
	cd analyzer && .venv/bin/python -m pytest tests/ -q
	cd reporter && ../analyzer/.venv/bin/python -m pytest tests/ -q
	cd executor && ../analyzer/.venv/bin/python -m pytest tests/ -q

deploy: build
	$(TF) init -input=false
	$(TF) apply -input=false -auto-approve

seed:
	$(PY) scripts/seed.py

traffic:
	$(PY) scripts/seed.py --traffic

scan:
	aws lambda invoke --function-name secops-scanner \
		--invocation-type Event --payload '{}' /dev/null
	@echo "async scan started; analyzer and reporter chain automatically"
	@echo "dashboard: $$($(TF) output -raw dashboard_url)"

report:
	aws lambda invoke --function-name secops-reporter \
		--cli-read-timeout 180 --payload '{}' /tmp/reporter-out.json > /dev/null
	@cat /tmp/reporter-out.json

destroy:
	$(PY) scripts/purge_evidence.py
	$(PY) scripts/seed.py --destroy
	$(TF) destroy -input=false -auto-approve

clean:
	rm -rf scanner/build analyzer/build reporter/build executor/build
