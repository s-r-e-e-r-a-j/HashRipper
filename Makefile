CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11
CPPFLAGS += -Iinclude
LDLIBS += -lcrypto -lz -lxxhash -pthread

TARGET = hashripper
SOURCES = src/main.c src/hash.c src/cracker.c src/pbkdf2.c src/scrypt.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDLIBS) -o $@

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
