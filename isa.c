////xsendl00
//ISA

#define __USE_BSD
#define __FAVOR_BSD
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <iostream>
#include <fstream>
#include <set>
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include "pcap.h"

using namespace std;
#define BUF 100
#define ROZ 4
#define CISLO 10 

#define MIN(X,Y) ( (X) < (Y) ? (X) : (Y) )
#define MAX(X,Y) ( (X) > (Y) ? (X) : (Y) )

//////struktura parametru
////////////////////////
typedef struct argument {
   unsigned short pt;   // aktivni v 1 
   unsigned short pu;   // aktivni v 1
   unsigned short typ_prekladu;  // 1 domain name, 2 IP
   int *polept;
   char rozhrani[ROZ];   // 1 = em0; 2 = ...
   char hostname_ip[BUF];
   char addres[BUF];
}  TArgum;


/////////////////////////////
////  pomocna TCP header
////////
// pro generovani kontrolniho souctu

struct pom_tcp_head {
   struct in_addr src;
   struct in_addr dst;
   unsigned char pad;
   unsigned char protocol;
   unsigned short tcp_len;
   struct tcphdr tcp_head;
};
/////////////////////////////

/////////////////////////////
///   parsrovani argumentu
////////////////////////////
void parserArg(int argc, char *argv[], TArgum &params) {

//vyprazdneni strukturu
   memset(params.hostname_ip, '\0', sizeof(params.hostname_ip));
   memset(params.addres, '\0', sizeof(params.addres));
   params.pt = 0;
   params.pu = 0;

   int carka = 0;
   int pomlcka = 0;
   int mod = 0;
   int pozice = 0;
   char cislo[CISLO];
   memset(cislo, '\0', sizeof(cislo));
   //int *polept;

   for(int i = 1; i < argc; i++)
   {
      if( (argv[i][0] == '-') && (argv[i][2] == 't')
                              && (argv[i][1] == 'p'))
      {
//zpracovani portu ARGPT
         //port nezacina '-' ani ','
         if( argv[i+1][0] != '-' && argv[i+1][0] != ',' ) 
         {
            for( pozice = 0; argv[i+1][pozice] != '\0'; pozice ++ )
            {
               if( argv[i+1][pozice] == ',' )//obsahuje ','
               { 
                  mod = 2;
                  carka++;
               }
               else if( argv[i+1][pozice] == '-' )//obsahuje '-'
               { 
                  if( pomlcka != 0 )
                  {
                     //bud zrusit nebo pouzit cast pro argumentu
                     fprintf(stderr, "MOD3 vickrat pomlcka\n");
                     break;
                  }
                  pomlcka++;
                  mod = 3;
                  carka = 4;
               }
//dodelat,poresit co nastane kdyz spatne zadany port
               else if( isdigit(argv[i+1][pozice]) == 0 ) //neni cislo
               {
                  fprintf(stderr, "CHYBA parametru, neni cislo\n");
               }
            }
         }
         if( mod == 0 ) //port zadan jednim cislem
         {
            mod = 1;
            carka = 3;
         }
         else if( mod == 2)
         {
            carka = carka + 3;
         }

         //alokace pole 
         int pozice1 = 0;//pozice pri nacitani cisla, pom, pole
         int pozice2 = 2;//pozice pro nacitani portu do pole
         params.polept = (int*)malloc(carka * sizeof(int));//nezapomenout uvolnit
         memset(params.polept, '\0', sizeof(params.polept));
         params.polept[0] = mod;
         params.polept[1] = carka;
         pomlcka = 0;
         //naplneni pole, cisl
         if( mod == 1 )
         {  //kontrola rozsahu velikosti portu
            if( atoi(argv[i+1]) > 0 && atoi(argv[i+1]) <= 65535 )
            {
              params.polept[2] = atoi(argv[i+1]);
            }
            else //vytvorit fci na vypis chyb
            {
               fprintf(stderr, "CHYBA MOD1 spatne rozsah portu\n");
            }
         }
         else if( mod == 2 )
         {
            for( pozice = 0; argv[i+1][pozice] != '\0'; pozice++ )
            {
               if( isdigit(argv[i+1][pozice]) != 0 )
               {
                  cislo[pozice1] = argv[i+1][pozice];
                  pozice1++;
               }
               else if( argv[i+1][pozice] == ',' )
               {
                  if( atoi(cislo) > 0 && atoi(cislo) <= 65355 )
                  {
                     params.polept[pozice2] = atoi(cislo);//ulozeni cisla do pole
                     pozice2++;
                  }
                  else
                  {
                     fprintf(stderr, "MOD2 port cislo %d je vynechan, lezi mimo rozsah povolenych portu\n",atoi(cislo));
                  }
                  pozice1 = 0;
                  memset(cislo, '\0', sizeof(cislo));
               }
               else
               {
                  fprintf(stderr, "MOD2 neni vyresena drivejsi kontrola\n");
               }
            }
            params.polept[pozice2] = atoi(cislo);//ulozeni posldeniho cisla do pole
         }
         //pracuje tak ze vezme jen dobrou cast z portu
         else if( mod == 3 )//mod rozsah portu
         {
            for( pozice = 0; argv[i+1][pozice] != '\0'; pozice++ )
            {
               if( isdigit(argv[i+1][pozice]) != 0 )
               {
                  cislo[pozice1] = argv[i+1][pozice];
                  pozice1++;
               }
               else if( argv[i+1][pozice] == '-' )//nemuselo by se
               {
                  //vynecha druhou cats za pmlckouo
                  if( pomlcka == 0)
                  {
                     params.polept[2] = atoi(cislo);
                     pozice1 = 0;
                     memset(cislo, '\0', sizeof(cislo));
                     pomlcka++;
                  }
                  else if( pomlcka == 1)
                  {
                     printf("pomlcka ----------%d-\n",atoi(cislo));
   
                     params.polept[3] = atoi(cislo);
                     pomlcka = 2;
                    // memset(cislo, '\0', sizeof(cislo));
                  }
                  //break;
                  //memset(cislo, '\0', sizeof(cislo));
               }
               else//nemuze nastat
               {
                  printf("nemelo nastat\n");
               }
            }
            if( pomlcka == 1 )
            {
               params.polept[3] = atoi(cislo);
            }
         }
         else  //nemelo by nastat
         {
            printf("neocekavana chyba, pokracujte smela dal :) \n");
         } 

         i++;
         params.pt = 1;
      }
      else if( (argv[i][0] == '-') && (argv[i][2] == 'u')
                                   && (argv[i][1] == 'p')
             ) 
      {
         //zpracovani FCE PU----------SPUSTI SE FCE PU


         //zpracovani portu ARGPU
         i++;
      }
      else if( argv[i][0] == '-' && argv[i][1] == 'i')
      {
         if( argv[i+1][0] == 'e' && argv[i+1][1] == 'm'
                                 && argv[i+1][2] == 0)
      memset(params.rozhrani, '\0', sizeof(params.rozhrani));
         for(int l=0;argv[i+1][l]!='\0';l++)params.rozhrani[l]=argv[i+1][l];
         printf("ppppp %s \n",params.rozhrani);
         if( argv[i+1][0] == 'l' && argv[i+1][1] == 0);
         i++;
      }
      else if( argv[i][0] == '-')
      {
         //cybny parametr
      }
      else
      {
         //zpracovani IP adresy nebo domain name
         if( isdigit(argv[i][0]) == 0 )
         {
            //domain name
           params.typ_prekladu = 1;
            for( int k = 0; argv[i][k] != '\0'; k++ )
            {
              params.addres[k] = argv[i][k];
            }
         }
         else
         {
            //adresa ve forme IP
            params.typ_prekladu = 2;
            for( int k =0; argv[i][k] != '\0'; k++ )
            {
               params.addres[k] = argv[i][k];
            }
            printf("cislo\n");
         }
      }

   }
////////////////////////////////////
///kontrolni vypisy
         printf("carka %d \n",carka);
        // for(int i = 0; i <  carka; i++)
         for(int i = 0; params.polept[i] != '\0';i++)
         {
            printf("pole portu  %d\n",params.polept[i]);
         }
} 

////////////////////////////////////
//// kontrolni soucet
///////////////////////////////////
int checkSum( unsigned short *datagram, int nwords ) {
   unsigned long sum;
   for( sum = 0; nwords > 0; nwords-- ) sum += *datagram++;
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   return ~sum;
}
////////////////////////////////////

unsigned short checkSumTCP( TArgum params ) {

   struct pom_tcp_head buf;
   u_short ans;

   memset(&buf, 0, sizeof(buf));
//   buf.src.s_addr = ;
//   buf.dst.s_addr = ;
   buf.pad = 0;
   buf.protocol = IPPROTO_TCP;
//   buf.tcp_len = htons(len);
//   ans = checkSum((unsigned short *)&buf, 12 + len);
   return ans;
}

///////////////////////////////////
////  vytvoreni socketu
//////////////////////////////////
int openSocket( int *mSocket) {
   //int chyba = 0;
   
if( (*mSocket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP) ) < 0 )
   {
      //chyba = -1;
      //return chyba;
   }
   return 1;// chyba
}
///////////////////////////////
////  naplneni struktury IP hlavicky
//////////////
// unsigned char ip_hl:4, ip_v:4
// unsigned char ip_tos;
// unsigned short int ip_len; //celkova delak datagramu v bytech i hlavicka
// unsigned short int ip_id;  //slouzi potrebam fragmentace
                              //vsechny fragmenty ze stejenho celku maji v teto polozce stejnou hodnotu
                              //podle toho se pozna ze patri k sobe
// unsigned short int ip_off; //offset fragmentu dat od zacatku puvodniho celku
// unsigned char ip_ttl;   //Time To Live
                           //fakticky citac pruchodu pres smerovace
                           //slouzi k detekci zacykleni
// unsigned char ip_p;  //udava typ uzitecneho nakladu
                        //1=ICMP, 4=IP over IP(tunelovani
                        //6=TCP, 17=UDP
// unsigned short int ip_sum; //kontrolni soucet hlavicky
                              //pocitany jako 1-vy doplnek
// unsigned int ip_src; //zdrojova IP adresa
// unsigned int ip_dst; //cilova IP adresa
/////////////////////////////////////
void  fillIP(struct ip* ip_head, struct sockaddr_in sin) {

   ip_head->ip_hl = 5;  // velikost hlavicky (typisky 20 bytu)
   ip_head->ip_v = 4;   // verze IP protokolu
   ip_head->ip_tos = 0;
   ip_head->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
   ip_head->ip_id = htonl(54321);
   ip_head->ip_off= 0;
   ip_head->ip_ttl = 255;
   ip_head->ip_p = 6;   //IPPROTO_TCP
   ip_head->ip_sum = 0; //prozatim nula, po vypoctu se doplni
   ip_head->ip_src.s_addr = inet_addr("192.168.2.102");//doplnit IP adresu
   ip_head->ip_dst.s_addr = sin.sin_addr.s_addr;

}

///////////////////////////////////////////////////////
////  naplneni struktoy TCP hlavicky
////////////////
//
void fillTCP(struct tcphdr* tcp_head, int i) {
   tcp_head->th_sport = htons(12234);   //doplnit cilso portu(zdrojovy)
   tcp_head->th_dport = htons(i);   //doplnit port(cilovy)
   tcp_head->th_seq = random();
   tcp_head->th_ack = 0;
   tcp_head->th_x2 = 0;
   tcp_head->th_off = 0;
   tcp_head->th_flags = TH_SYN;
   tcp_head->th_win = htonl(65535);
   tcp_head->th_sum = 0;
   tcp_head->th_urp = 0;
}
/*
////////////////////////////////////////
//// zjisteni IP adresy interfacu
/////////////////////////
void ipInterface( TArgum params ) {

   pcap_if_t *device;

   char *errbuf;
   pcap_findalldevs(&device, errbuf);
   pcap_addr_t *adresa;
  // if(device->name == params.rozhrani)
   printf("....device%s.. \n ", params.rozhrani);
  // for(device;device->name == params.rozhrani; device = device->next)
  // {
      printf("------------- %s... \n",device->name);
      printf("------------- %02x \n",device->addresses->addr->sa_data[0]);
      int i = 0;

      adresa = device->addresses;

    pcap_if_t *d;
  //    for(d=device;d;d=d->next)
  //    {   
   //      printf("------------- %s \n",device->addresses->netmask);
         printf("......................%d, %s \n",++i, d->name);
  //       if(d->description)
  //          printf("des (%s)\n",d->description);
  //       else
  //          printf("neni\n");
  //    }
   struct sockaddr_in *addres = (struct sockaddr_in *)(adresa->addr);
   SOURCE_ADDRESS.assign(inet_ntoa(addres->sin_addr)); 
}
*/


///////////////////////////////
///   main
///////////////////////////////
int main( int argc, char *argv[] ) {

   TArgum params;
   parserArg(argc, argv, params);   // volani FCE pro argumenty
  
   


   //ipInterface(params);
   int mSocket;
   openSocket( &mSocket);

   if( params.pt == 1 )  // TCP scanning
   {

      char datagram[4096]; // bufer, obsahuje IP hlavicku a TCP hlavicku
   
      struct ip *ip_head = (struct ip *) datagram; // IP hlavika 
      struct tcphdr *tcp_head = (struct tcphdr *) ( datagram + sizeof( struct ip) );   // TCP hlavicka
      struct sockaddr_in sin;
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = inet_addr(params.addres);
      sin.sin_port = htons(12234);
      memset( datagram, 0, 4096);   // vynulovani datagramu
//pridat kontrolni soucet
      if(params.polept[0] == 3)  //nastaveni MAx, MIN portu u rozsahu
      {
         int max = MAX(params.polept[2], params.polept[3]);
         int min = MIN(params.polept[2], params.polept[3]);
         params.polept[2] = min;
         params.polept[3] = max;
         printf("max : %d, min : %d \n", params.polept[3],params.polept[2]);
      }
   
      for(int i = 2; params.polept[i] != '\0'; i++)
      {
         if(params.polept[0] == 3)  //porty zadany pomoci rozsahu
         {
            for( int l = params.polept[2]; l <= params.polept[3]; l++)
            {
               printf("cislo portu :  %d \n",l);
               fillTCP(tcp_head, l);
            }
            i++;
         }
         else
         {
            fillIP(ip_head, sin);     // naplneni IP hlavicky
            fillTCP(tcp_head, params.polept[i]);    // naplneni TCP hlavicky
            printf("tcp %d \n",ip_head->ip_sum);
  printf(" tcp_head->th_dport: %d\n",tcp_head->th_dport);   //doplnit port(cilovy)
         }
      }
   }
   if( params.pu == 1 ) // UDP scanning
   {

   }
   return 1;
}
