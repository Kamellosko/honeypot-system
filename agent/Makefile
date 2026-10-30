CC ?= cc
OBJCOPY ?= objcopy
STRIP ?= strip
INSTALL_BINARY ?= build/release/honeypot
.DELETE_ON_ERROR:
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror
# GCC 11 (AlmaLinux 9) supports _FORTIFY_SOURCE up to 2 and -Werror turns level 3 into an error.
# On a newer toolchain (AlmaLinux 10, gcc-toolset-14) build with FORTIFY_LEVEL=3.
FORTIFY_LEVEL ?= 2
HARDEN_CFLAGS = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$(FORTIFY_LEVEL) -fstack-protector-strong -fPIE -fvisibility=hidden
HARDEN_LDFLAGS = -pie -Wl,-z,relro,-z,now,-z,noexecstack -Wl,--build-id=sha1
INCLUDES = -Iinclude -Ithird_party/cJSON
LDLIBS += -lcurl -lcrypto -ltdb -lpthread -lm
SOURCES = src/main.c src/config.c src/monitor.c src/snapshot.c src/protocol.c src/port.c src/heartbeat.c src/network.c src/connections.c src/diff.c src/io.c
TEST_COMMON = src/snapshot.c src/protocol.c
TESTS = config snapshot binary monitor root_rebind rename_overwrite log protocol transport heartbeat network connections diff io

.PHONY: all check clean install release check-release install-release
all: build/honeypot

build:
	mkdir -p build

build/cJSON.o: third_party/cJSON/cJSON.c Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) -Wno-implicit-fallthrough -c $< -o $@

build/honeypot: $(SOURCES) $(wildcard include/*.h) Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $(SOURCES) $(LDLIBS) -o $@

build/%_test: tests/%_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -o $@

build/https_send: tests/https_send.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=curl_easy_init -o $@

build/allocation_test: tests/allocation_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=strdup -Wl,--wrap=strndup -o $@

build/state_failure_test: tests/state_failure_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=renameat -o $@

build/report_failure_test: tests/report_failure_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=hp_write_text_diff -o $@

build/network_test: tests/network_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=getifaddrs -Wl,--wrap=freeifaddrs -Wl,--wrap=socket -Wl,--wrap=ioctl -Wl,--wrap=close -o $@

build/connection_poll_test: tests/connection_poll_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=socket -Wl,--wrap=setsockopt -Wl,--wrap=sendto -Wl,--wrap=recvmsg -Wl,--wrap=close -Wl,--wrap=hp_lookup_mac -o $@

build/heartbeat_test: tests/heartbeat_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=getrandom -o $@

build/report_id_test: tests/report_id_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=RAND_bytes -o $@

build/log_test: tests/log_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=read -o $@

build/transport_failure_test: tests/transport_failure_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=curl_easy_setopt -Wl,--wrap=curl_easy_perform -Wl,--wrap=curl_easy_getinfo -o $@

build/wipe_test: tests/wipe_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/cJSON.o $(LDLIBS) -Wl,--wrap=free -o $@

build/main_test.o: src/main.c $(wildcard include/*.h) Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) -Dmain=hp_agent_main -c $< -o $@

build/lifecycle_test: tests/lifecycle_test.c $(filter-out src/main.c,$(SOURCES)) $(wildcard include/*.h) build/main_test.o build/cJSON.o Makefile | build
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) -UHEARTBEAT_INTERVAL -DHEARTBEAT_INTERVAL=1 $(LDFLAGS) $(HARDEN_LDFLAGS) $< $(filter-out src/main.c,$(SOURCES)) build/main_test.o build/cJSON.o $(LDLIBS) -Wl,--wrap=hp_store_init -Wl,--wrap=hp_discover_sources -Wl,--wrap=hp_send_pending -Wl,--wrap=hp_connections_poll -o $@

check: $(addprefix build/,$(addsuffix _test,$(TESTS))) build/honeypot build/https_send build/report_failure_test build/lifecycle_test build/wipe_test build/connection_poll_test build/report_id_test build/transport_failure_test build/state_failure_test build/allocation_test
	@set -eu; for test in $(TESTS); do build/$${test}_test; done
	@build/report_failure_test
	@build/lifecycle_test
	@build/wipe_test
	@build/connection_poll_test
	@build/report_id_test
	@build/state_failure_test
	@build/allocation_test
	@build/transport_failure_test
	@python3 tests/diff_roundtrip.py build/diff_test
	@python3 tests/https_integration.py build/https_send
	@build/honeypot --id x --ip bad --port 443 >/dev/null 2>&1; test $$? -eq 2
	@build/honeypot --id x --ip 127.0.0.1 --port 0 >/dev/null 2>&1; test $$? -eq 2
	@build/honeypot --id x --ip 127.0.0.1 --port 443 --extra z >/dev/null 2>&1; test $$? -eq 2

clean:
	rm -rf build

# Staging via DESTDIR never enables or starts a host service.
install: $(INSTALL_BINARY)
	@test -n "$(DESTDIR)" || test "$$(id -u)" -eq 0
	install -d -m 0755 "$(DESTDIR)/usr/local/sbin" "$(DESTDIR)/etc/systemd/system"
	install -m 0700 "$(INSTALL_BINARY)" "$(DESTDIR)/usr/local/sbin/sys-auditd"
	install -m 0600 packaging/sys-auditd.service "$(DESTDIR)/etc/systemd/system/sys-auditd.service"
	@test ! -L "$(DESTDIR)/var/lib/sys-auditd"
	install -d -m 0700 "$(DESTDIR)/var/lib/sys-auditd"
	chmod 0700 "$(DESTDIR)/var/lib/sys-auditd"
	@if test -z "$(DESTDIR)"; then chown root:root /usr/local/sbin/sys-auditd /etc/systemd/system/sys-auditd.service /var/lib/sys-auditd; fi

# Keep the full local build for diagnostics; install only the stripped artifact.
build/release:
	mkdir -p $@

build/release/honeypot.full: $(SOURCES) $(wildcard include/*.h) Makefile | build/release
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(HARDEN_CFLAGS) -O2 -g $(LDFLAGS) $(HARDEN_LDFLAGS) $(SOURCES) $(LDLIBS) -o $@
	chmod 0700 $@

build/release/honeypot build/release/honeypot.debug &: build/release/honeypot.full
	$(OBJCOPY) --only-keep-debug $< build/release/honeypot.debug
	chmod 0600 build/release/honeypot.debug
	cp $< build/release/honeypot
	$(STRIP) --strip-unneeded build/release/honeypot
	$(OBJCOPY) --add-gnu-debuglink=build/release/honeypot.debug build/release/honeypot

release: build/release/honeypot build/release/honeypot.debug

check-release: check release
	python3 tests/release_test.py build/release/honeypot build/release/honeypot.debug

install-release: release
	$(MAKE) install INSTALL_BINARY=build/release/honeypot
