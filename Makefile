.PHONY: build test demo demo-offline pi-build install uninstall

pi-build:
	cd pi && npm install --ignore-scripts && npm run hydrate:model-data && npm run build:offline

build:
	cd core && go build -o bin/avhsol ./cmd/avhsol

test:
	cd guard && cargo build --release -q && cargo test -q
	cd core && go test ./...
	cd pi/packages/avhsol && npx vitest --run

# Pipeline check with a simulated gullible model (no LLM needed).
demo-offline: build
	./core/bin/avhsol campaign -offline -regress

# Guard + API + dashboard together. AVHSOL_OFFLINE=1 makes runs default to the simulated model.
demo:
	AVHSOL_OFFLINE=1 ./scripts/demo.sh

# User-level install (no sudo): ~/.local/bin/avhsol, avhsol-proxy, avhsol-sandbox and ~/.local/share/avhsol
install:
	./scripts/install.sh

uninstall:
	./scripts/install.sh --uninstall
