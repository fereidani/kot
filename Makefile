PREFIX ?= /usr/local
RUSTUP = curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# The release binary is linked statically against musl. The runtime is
# executed twice per container, once as the driver and once as the
# container's init, and a dynamically linked binary pays the loader both
# times: about a millisecond and a half per container on a stock host.
# The target is the host's own with its C library swapped for musl.
TARGET ?= $(shell rustc -vV | sed -n 's/^host: //p' | sed 's/-gnu\(eabi[a-z]*\)\{0,1\}$$/-musl\1/')
BINARY = target/$(TARGET)/release/kot

build: require-cargo
	cargo build --release --target $(TARGET)

clean: require-cargo
	cargo clean

install:
	@test -x $(BINARY) || { echo "$(BINARY) missing, run 'make' first"; exit 1; } >&2
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/kot

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/kot

require-cargo:
	@command -v cargo >/dev/null || { echo "cargo not found, install Rust with:"; echo "  $(RUSTUP)"; exit 1; } >&2

.PHONY: build clean install uninstall require-cargo
