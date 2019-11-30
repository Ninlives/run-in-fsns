PREFIX := /usr

run-in-fsns: *.c
	$(CC) -o $@ $^

all: run-in-fsns
install: all
	install -m 755 -D -t $(PREFIX)/bin run-in-fsns
