LFLAGS = -I../src -L../src -lssl -lcrypto -ludt -lstdc++ -lpthread
CXX?=g++

all: tls_client tls_server

tls_common.o: tls_common.cpp tls_common.h e_os.h
	$(CXX) tls_common.cpp -c $(LFLAGS)

tls: tls_client tls_server

tls_client: tls_common.o tls_client.cpp
	$(CXX) $^ -o $@ $(LFLAGS)

tls_server: tls_common.o tls_server.cpp
	$(CXX) $^ -o $@ $(LFLAGS)

