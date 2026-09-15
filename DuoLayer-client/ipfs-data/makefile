# =========================
# Build Configuration
# =========================

# The experiment launcher may invoke make from a non-login /bin/sh.  In that
# environment neither Rustup nor a manually installed Go toolchain is
# necessarily present in PATH, so resolve both tools explicitly while still
# allowing callers to override them (for example, CARGO=/opt/rust/bin/cargo).
GO ?= $(firstword $(shell command -v go 2>/dev/null) $(wildcard /usr/local/go/bin/go) $(wildcard /usr/bin/go))
CARGO ?= $(firstword $(shell command -v cargo 2>/dev/null) $(wildcard /root/.cargo/bin/cargo) $(wildcard /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo))

ifeq ($(strip $(GO)),)
$(error Go compiler not found; install Go or invoke make with GO=/path/to/go)
endif
ifeq ($(strip $(CARGO)),)
$(error Cargo not found; install Rust or invoke make with CARGO=/path/to/cargo)
endif

GOOS := linux
GOARCH := amd64
CGO_ENABLED := 1
# Client binaries are copied into Alpine-based IPFS containers.  The audited
# Rust core is linked through cgo, therefore build one fully static Linux
# executable instead of depending on the host's glibc loader inside Alpine.
BUILD_FLAGS := -trimpath -ldflags '-s -w -linkmode external -extldflags "-static"'

# 源码子目录（除了 cmd）
SRCDIRS := dataRetrieve dataStorage systemInit policyUpdate attributeUpdate dataDecrypt

# 输出目录
BINDIR := cmd

# 生成的可执行文件路径
BINARIES := $(foreach dir,$(SRCDIRS),$(BINDIR)/$(dir))

# =========================
# Default Target
# =========================

.PHONY: all rust-core
all: rust-core $(BINARIES)

rust-core:
	@echo "Building audited PolyLock Rust core..."
	@cd ../polylock-v2/crypto-rust && $(CARGO) build --release

# =========================
# Build Rules
# =========================

$(BINDIR)/%: % rust-core
	@echo "🔨 Building $@ ..."
	@cd $< && \
		CGO_ENABLED=$(CGO_ENABLED) \
		GOOS=$(GOOS) \
		GOARCH=$(GOARCH) \
		$(GO) build $(BUILD_FLAGS) -o ../$(BINDIR)/$(notdir $@)
	@chmod +x $@
	@echo "✅ Built $@"

# =========================
# Clean Target
# =========================

.PHONY: clean
clean:
	@echo "🧹 Cleaning binaries..."
	@rm -rf $(BINARIES)
	@rm -rf $(BINDIR)/*
	@echo "✅ Clean complete"
