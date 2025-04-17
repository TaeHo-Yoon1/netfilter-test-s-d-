CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lnetfilter_queue

TARGET = netfilter-test
SRCS = netfilter.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS) 