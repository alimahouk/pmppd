CC=clang
CFLAGS=-I /usr/local/include -I.

ODIR=obj

LIBS=-lssl -lcrypto -lz -pthread -lpthread -luuid 
LIBDIRS=/usr/local/lib

DEPS = crypto.h io.h main.h net.h pmpp.h pmpptypes.h util.h

_OBJ = crypto.o io.o  main.o net.o pmpp.o util.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pmpp_test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) -L$(LIBDIRS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 