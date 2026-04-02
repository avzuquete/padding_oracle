CFLAGS = -g

po: po.o
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
