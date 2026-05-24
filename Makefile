CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -g
TARGET  = editor
SRCDIR  = src
SRCS    = $(SRCDIR)/editor.c $(SRCDIR)/compress.c $(SRCDIR)/crypto.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(SRCDIR)/*.o $(TARGET) test_output.bin test_input.txt test_recovered.txt

# Test rápido: genera archivo de prueba, comprime+cifra, descifra+descomprime
test: all
	@echo "=== Test de integridad del pipeline ==="
	@python3 -c "print('A' * 10000 + 'B' * 5000 + 'C' * 8000)" > test_input.txt
	@echo "Archivo original: $$(wc -c < test_input.txt) bytes"
	@EDITOR_KEY="secretkey123" ./editor write test_output.bin < test_input.txt
	@echo "Archivo cifrado+comprimido: $$(wc -c < test_output.bin) bytes"
	@EDITOR_KEY="secretkey123" ./editor read test_output.bin > test_recovered.txt
	@diff test_input.txt test_recovered.txt
	@echo "✓ Integridad verificada: los datos recuperados son idénticos"
	@rm -f test_input.txt test_output.bin test_recovered.txt
