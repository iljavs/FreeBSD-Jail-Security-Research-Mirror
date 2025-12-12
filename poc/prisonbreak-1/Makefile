CC = cc
CFLAGS =
LDFLAGS = -lpthread

all: prisonbreak

prisonbreak: prisonbreak.c
	$(CC) -o $@ $< $(LDFLAGS)

clean:
	rm -f prisonbreak prisonbreak.ko
