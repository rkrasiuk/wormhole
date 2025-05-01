.PHONY: build-program-sp1
build-program-sp1:
	cd programs/sp1 && cargo prove build

.PHONY: build-program-risc0
build-program-risc0:
	cargo risczero build -p wormhole-program-risc0

.PHONY: build-program-pico
build-program-pico:
	cd programs/pico && cargo pico build
