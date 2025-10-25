CC = gcc
CFLAGS = -Wall -Wextra -O3 -pthread
TARGET = aeza_bypass
SOURCE = aeza_bypass.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
