CC = gcc
CFLAGS = -Wall -Wextra -pedantic -pthread
LDFLAGS = -pthread
SRCS = main.c log_analyzer.c config.c
OBJS = $(SRCS:.c=.o)
TARGET = log_analyzer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean 