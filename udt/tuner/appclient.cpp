#ifndef WIN32
   #include <unistd.h>
   #include <cstdlib>
   #include <cstring>
   #include <netdb.h>
#else
   #include <winsock2.h>
   #include <ws2tcpip.h>
   #include <wspiapi.h>
#endif
#include <iostream>
#include <udt.h>
#include "cc.h"

using namespace std;

#ifndef WIN32
void* monitor(void*);
#else
DWORD WINAPI monitor(LPVOID);
#endif

int main(int argc, char* argv[])
{
   if (argc != 8)
   {
      cout << "usage: appclient server_ip server_port use_blast(0 or 1) udt_sendbuff udp_sendbuff mss" << endl;
      return 0;
   }

   // use this function to initialize the UDT library
   UDT::startup();

   struct addrinfo hints, *local, *peer;

   memset(&hints, 0, sizeof(struct addrinfo));

   hints.ai_flags = AI_PASSIVE;
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM;
   //hints.ai_socktype = SOCK_DGRAM;

   if (0 != getaddrinfo(NULL, "9000", &hints, &local))
   {
      cout << "incorrect network address.\n" << endl;
      return 0;
   }

   UDTSOCKET client = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);

    int blast = atoi(argv[3]);
    int udt_sendbuff = atoi(argv[4]);
    int udp_sendbuff = atoi(argv[5]);
    int mss = atoi(argv[6]);
    int blast_rate = atoi(argv[7]);


   // UDT Options
   if (blast)
    UDT::setsockopt(client, 0, UDT_CC, new CCCFactory<CUDPBlast>, sizeof(CCCFactory<CUDPBlast>));

   UDT::setsockopt(client, 0, UDT_MSS, &mss, sizeof(int));
   UDT::setsockopt(client, 0, UDT_SNDBUF, &udt_sendbuff, sizeof(int));
   UDT::setsockopt(client, 0, UDP_SNDBUF, &udp_sendbuff, sizeof(int));

   // Windows UDP issue
   // For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
   #ifdef WIN32
      UDT::setsockopt(client, 0, UDT_MSS, new int(1052), sizeof(int));
   #endif

   // for rendezvous connection, enable the code below
   /*
   UDT::setsockopt(client, 0, UDT_RENDEZVOUS, new bool(true), sizeof(bool));
   if (UDT::ERROR == UDT::bind(client, local->ai_addr, local->ai_addrlen))
   {
      cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }
   */

   freeaddrinfo(local);

   if (0 != getaddrinfo(argv[1], argv[2], &hints, &peer))
   {
      cout << "incorrect server/peer address. " << argv[1] << ":" << argv[2] << endl;
      return 0;
   }

   // connect to the server, implict bind
   if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
   {
      cout << "connect: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }

   freeaddrinfo(peer);

   // using CC method
   if (blast) {
       CUDPBlast* cchandle = NULL;
       int temp;
       UDT::getsockopt(client, 0, UDT_CC, &cchandle, &temp);
       if (NULL != cchandle)
          cchandle->setRate(blast_rate);
    }

   int size = udt_sendbuff;
   char* data = new char[size];

   #ifndef WIN32
      pthread_create(new pthread_t, NULL, monitor, &client);
   #else
      CreateThread(NULL, 0, monitor, &client, 0, NULL);
   #endif

   for (int i = 0; i < 1000000; i ++)
   {
      int ssize = 0;
      int ss;
      while (ssize < size)
      {
         if (UDT::ERROR == (ss = UDT::send(client, data + ssize, size - ssize, 0)))
         {
            cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
            break;
         }

         ssize += ss;
      }

      if (ssize < size)
         break;
   }

   UDT::close(client);

   delete [] data;

   // use this function to release the UDT library
   UDT::cleanup();

   return 1;
}

#ifndef WIN32
void* monitor(void* s)
#else
DWORD WINAPI monitor(LPVOID s)
#endif
{
   UDTSOCKET u = *(UDTSOCKET*)s;

   UDT::TRACEINFO perf;

   cout << "SendRate(Mb/s)\tRTT(ms)\tCWnd\tPktSndPeriod(us)\tRecvACK\tRecvNAK" << endl;

   while (true)
   {
      #ifndef WIN32
         sleep(1);
      #else
         Sleep(1000);
      #endif

      if (UDT::ERROR == UDT::perfmon(u, &perf))
      {
         cout << "perfmon: " << UDT::getlasterror().getErrorMessage() << endl;
         break;
      }

      cout << perf.mbpsSendRate << "\t\t"
           << perf.msRTT << "\t"
           << perf.pktCongestionWindow << "\t"
           << perf.usPktSndPeriod << "\t\t\t"
           << perf.pktRecvACK << "\t"
           << perf.pktRecvNAK << endl;
   }

   #ifndef WIN32
      return NULL;
   #else
      return 0;
   #endif
}
