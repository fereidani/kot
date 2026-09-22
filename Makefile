PREFIX ?= /usr/local
RUSTUP = curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

build: require-cargo
	cargo build --release

clean: require-cargo
	cargo clean

install:
	@test -x target/release/kot || { echo "target/release/kot missing, run 'make' first"; exit 1; } >&2
	install -Dm755 target/release/kot $(DESTDIR)$(PREFIX)/bin/kot

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/kot

require-cargo:
	@command -v cargo >/dev/null || { echo "cargo not found, install Rust with:"; echo "  $(RUSTUP)"; exit 1; } >&2

.PHONY: build clean install uninstall require-cargo
