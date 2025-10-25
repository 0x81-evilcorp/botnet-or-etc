CC = clang
CFLAGS = -Wall -Wextra -O2 -std=c99

# все bypass методы
TARGETS = synack_bypass psh_bypass urg_bypass fin_bypass rst_bypass combo_bypass lowrate_bypass ml_bypass handshake_flood connection_exhaust

all: $(TARGETS)

synack_bypass: synack_bypass.c
	$(CC) $(CFLAGS) -o synack_bypass synack_bypass.c

psh_bypass: psh_bypass.c
	$(CC) $(CFLAGS) -o psh_bypass psh_bypass.c

urg_bypass: urg_bypass.c
	$(CC) $(CFLAGS) -o urg_bypass urg_bypass.c

fin_bypass: fin_bypass.c
	$(CC) $(CFLAGS) -o fin_bypass fin_bypass.c

rst_bypass: rst_bypass.c
	$(CC) $(CFLAGS) -o rst_bypass rst_bypass.c

combo_bypass: combo_bypass.c
	$(CC) $(CFLAGS) -o combo_bypass combo_bypass.c

lowrate_bypass: lowrate_bypass.c
	$(CC) $(CFLAGS) -o lowrate_bypass lowrate_bypass.c

ml_bypass: ml_bypass.c
	$(CC) $(CFLAGS) -o ml_bypass ml_bypass.c

handshake_flood: handshake_flood.c
	$(CC) $(CFLAGS) -pthread -o handshake_flood handshake_flood.c

connection_exhaust: connection_exhaust.c
	$(CC) $(CFLAGS) -pthread -o connection_exhaust connection_exhaust.c

clean:
	rm -f $(TARGETS)

install: all
	cp $(TARGETS) /usr/local/bin/

.PHONY: all clean install
