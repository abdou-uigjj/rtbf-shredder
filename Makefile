.PHONY: help deps test drill policy policy-negative fmt validate lambda.zip release clean

help:
	@echo "rtbf-shredder - provable right-to-be-forgotten erasure"
	@echo "  deps            install python deps (pynacl, pytest)"
	@echo "  test            run the unit tests"
	@echo "  drill           run the provable gate (recovery attacker + ledger + cert)"
	@echo "  policy          conftest policy pack against k8s manifests"
	@echo "  policy-negative the bad fixtures must be rejected"
	@echo "  fmt             terraform fmt"
	@echo "  validate        terraform validate"
	@echo "  lambda.zip      build the responder lambda package"
	@echo "  release         build the release archives (v1.0.0)"
	@echo "  clean           remove local artifacts"

deps:
	pip install -r requirements.txt

test:
	python3 -m pytest tests/ -q

drill:
	python3 drill/rtbf_drill.py

policy:
	conftest test k8s/ --policy policy/

policy-negative:
	@conftest test examples/policy-negative/ --policy policy/ >/dev/null 2>&1 && \
		echo "the bad manifests passed - the policies guard nothing" && exit 1 || \
		echo "bad fixtures correctly rejected"

fmt:
	cd terraform && terraform fmt -recursive

validate:
	cd terraform && terraform init -backend=false && terraform validate

lambda.zip:
	python3 scripts/build_lambda_zip.py

release:
	bash scripts/release.sh

clean:
	rm -rf lambda.zip .pytest_cache build/
	find . -name __pycache__ -type d -exec rm -rf {} +
