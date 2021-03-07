CC     = gcc
CFLAGS = -Wall -Wextra -ansi -pedantic -O3
LDFLAGS =

BINDIR = bin
SRCDIR = src
OBJDIR = obj
INCLDIR = include

_BIN = aes_exec
BIN = $(addprefix $(BINDIR)/, $(_BIN)) 
SRC = $(wildcard $(SRCDIR)/*.c)
_OBJ = $(patsubst $(SRCDIR)/%.c, %.o, $(SRC))
OBJ = $(addprefix $(OBJDIR)/, $(_OBJ))


all:$(BIN)

$(BIN): $(BINDIR) $(OBJDIR) $(OBJ)
	$(CC) -o $(BIN) $(OBJ) $(LDFLAGS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I$(INCLDIR)

.PHONY: clean

clean:
	rm -rf $(OBJDIR) $(BINDIR)

