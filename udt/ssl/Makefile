LFLAGS = -I../src -L../src -lssl -lcrypto -ludt -lstdc++ -lpthread
CC = g++

all: tls_client tls_server

tls_common.o: tls_common.cpp tls_common.h e_os.h
	$(CC) tls_common.cpp -c $(LFLAGS)

tls: tls_client tls_server

tls_client: tls_common.o tls_client.cpp
	$(CC) $^ -o $@ $(LFLAGS)

tls_server: tls_common.o tls_server.cpp
	$(CC) $^ -o $@ $(LFLAGS)

