# Kompilator i nazwa pliku wykonywalnego
CC       := clang
TARGET   := agent

LLVM_PROFDATA := llvm-profdata-18
LLVM_COV      := llvm-cov-18

# Pliki źródłowe i nagłówkowe
SRCS     := agent.c main.c
OBJS     := $(SRCS:.c=.o)
HEADERS  := agent.h

CFLAGS_BASE := -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror

# Warianty kompilacji
CFLAGS_RELEASE := -O3 -flto -march=native
CFLAGS_DEV     := -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS_OPT     := -O3 -Rpass=loop-vectorize -Rpass-missed=loop-vectorize -Rpass-analysis=loop-vectorize
CFLAGS_COV     := -g -O0 -fprofile-instr-generate -fcoverage-mapping

.PHONY: all dev release sanitize opt-report analyze tidy coverage test clean help

# Domyślna kompilacja (Wersja z sanitizerami do bezstresowego deweloperki)
all: dev

# Build wydajnościowy (Release)
release: CFLAGS += $(CFLAGS_BASE) $(CFLAGS_RELEASE)
release: clean $(TARGET)
	@echo "[+] Zbudowano wersję zoptymalizowaną (Release)"

# Build deweloperski z sanitizerami (ASan + UBSan)
dev: sanitize

sanitize: CFLAGS += $(CFLAGS_BASE) $(CFLAGS_DEV)
sanitize: clean $(TARGET)
	@echo "[+] Zbudowano wersję z AddressSanitizer i UBSan"

# Build generujący raporty optymalizacji kompilatora Clang
opt-report: CFLAGS += $(CFLAGS_BASE) $(CFLAGS_OPT)
opt-report: clean $(TARGET)

# Reguła linkowania
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

# Reguła kompilacji plików .c do .o
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Analiza statyczna kodu za pomocą Clang Analyzer
analyze:
	@echo "[+] Uruchamianie Clang Static Analyzer..."
	$(CC) --analyze -Xanalyzer -analyzer-output=text $(SRCS)
	@echo "[+] Analiza statyczna zakończona."

# Linter Clang-Tidy
tidy:
	@echo "[+] Uruchamianie Clang-Tidy..."
	clang-tidy $(SRCS) -- -I.

# Pomiar pokrycia kodu (Code Coverage)
coverage: CFLAGS += $(CFLAGS_BASE) $(CFLAGS_COV)
coverage: clean $(TARGET)
	@echo "[+] Generowanie danych pokrycia kodu..."
	@./$(TARGET) --port 2222 --id "cov-sensor" & AGENT_PID=$$!; \
	sleep 0.2; \
	echo "Testowy payload pod coverage" | nc -w 1 127.0.0.1 2222 >/dev/null 2>&1 || true; \
	sleep 0.2; \
	kill -INT $$AGENT_PID 2>/dev/null || true; \
	wait $$AGENT_PID 2>/dev/null || true
	@llvm-profdata merge -sparse default.profraw -o default.profdata
	@llvm-cov report ./$(TARGET) -instr-profile=default.profdata
	@echo "[+] Aby wygenerować raport HTML, uruchom:"
	@echo "    llvm-cov show ./$(TARGET) -instr-profile=default.profdata -format=html -output-dir=coverage_html"

# Szybki test funkcjonalny z użyciem nc (netcat)
test: sanitize
	@echo "[+] Uruchamianie testu automatycznego..."
	@./$(TARGET) --port 2223 --id "test-sensor-01" & AGENT_PID=$$!; \
	sleep 0.2; \
	echo "TEST_PAYLOAD_DATA" | nc -w 1 127.0.0.1 2223; \
	sleep 0.2; \
	kill -INT $$AGENT_PID 2>/dev/null || true; \
	wait $$AGENT_PID 2>/dev/null || true
	@echo "[+] Test zakończony sukcesem."

# Czyszczenie katalogu
clean:
	rm -f $(OBJS) $(TARGET) *.plist *.profraw *.profdata
	rm -rf coverage_html
	@echo "[+] Wyczyszczono pliki kompilacji."

# Pomoc
help:
	@echo "Dostępne cele Makefile:"
	@echo "  make dev         - Kompilacja z AddressSanitizer i UBSan (domyślne)"
	@echo "  make release     - Kompilacja zoptymalizowana (-O3 -flto -march=native)"
	@echo "  make opt-report  - Kompilacja z raportowaniem wektoryzacji pętli (-Rpass)"
	@echo "  make test        - Uruchomienie automatycznego testu połaczenia z wysłaniem pakietu"
	@echo "  make analyze     - Statyczna analiza kodu Clang"
	@echo "  make coverage    - Wygenerowanie raportu pokrycia kodu (llvm-cov)"
	@echo "  make clean       - Usunięcie artefaktów kompilacji"
