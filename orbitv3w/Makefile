CC = clang
CFLAGS = -Wall -Wextra -O2 -std=c99 -pthread
TARGET = orbitv3
SOURCE = orbitv3.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
