.PHONY: build test demo demo-offline pi-build

pi-build:
	cd pi && npm install --ignore-scripts && npm run hydrate:model-data && npm run build:offline

build:
	cd core && go build -o bin/agentbreak ./cmd/agentbreak

test:
	cd core && go test ./...
	cd pi/packages/agentbreak && npx vitest --run

# Pipeline check with a simulated gullible model (no LLM needed).
demo-offline: build
	./core/bin/agentbreak campaign -offline -regress

# Guard + API + dashboard together. AGENTBREAK_OFFLINE=1 makes runs default to the simulated model.
demo:
	AGENTBREAK_OFFLINE=1 ./scripts/demo.sh
