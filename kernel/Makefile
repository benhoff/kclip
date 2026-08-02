# kclip out-of-tree kernel module

# ---- Version ----
# Prefer VERSION file; fall back to git describe; else 0.0.0
VERSION := $(shell (cat $(CURDIR)/VERSION) 2>/dev/null || git describe --tags --always 2>/dev/null || echo 0.0.0)

# ---- Paths / Config (override on command line if needed) ----
KDIR      ?= /lib/modules/$(shell uname -r)/build
DEST_DIR  ?= /lib/modules/$(shell uname -r)/extra
UAPI_DIR  ?= $(CURDIR)/include

# ---- Module names/sources ----
MODULE_NAME := kclip
obj-m       += $(MODULE_NAME).o

# Make kernel see our UAPI headers
ccflags-y += -I$(UAPI_DIR) -DCLIPBOARD_MODULE_VERSION=\"$(VERSION)\"

# --------------------
# Phony meta targets
# --------------------
.PHONY: all kmod clean kmod-clean install kmod-install uninstall print-vars

all: kmod

# --------------------
# Kernel module build
# --------------------
kmod:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

kmod-clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

# Install via manual copy into /extra (kept for compatibility)
install: kmod
	@sudo mkdir -p "$(DEST_DIR)"
	@sudo cp -v $(MODULE_NAME).ko "$(DEST_DIR)/"
	@sudo depmod -a
	@echo "Installed $(MODULE_NAME) v$(VERSION) to $(DEST_DIR)"

# Preferred: use kernel's modules_install path (places under /lib/modules/…)
kmod-install: kmod
	@sudo $(MAKE) -C $(KDIR) M=$(CURDIR) modules_install
	@sudo depmod -a
	@echo "Installed $(MODULE_NAME) v$(VERSION) via modules_install"

uninstall:
	@sudo rm -f "$(DEST_DIR)/$(MODULE_NAME).ko" || true
	@sudo depmod -a
	@echo "Removed $(MODULE_NAME) from $(DEST_DIR)"

clean: kmod-clean

# Debug helper
print-vars:
	@echo "VERSION   = $(VERSION)"
	@echo "KDIR      = $(KDIR)"
	@echo "DEST_DIR  = $(DEST_DIR)"
	@echo "UAPI_DIR  = $(UAPI_DIR)"

# ---- Kbuild footer (required by out-of-tree module builds) ----
# (kept at end so 'make -C $(KDIR) M=$(CURDIR) modules' can see it)
