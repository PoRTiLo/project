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

using namespace std;
#define BUF 100
#define CISLO 10 


//////struktura parametru
////////////////////////
typedef struct argument {
   int portTCP;
   int portUDP;
   char argPT[2];
   char argPU[2];
   char hostname[BUF];
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
   memset(params.argPT, '\0', sizeof(params.argPT));
   memset(params.argPU, '\0', sizeof(params.argPU));
   memset(params.hostname, '\0', sizeof(params.hostname));

   int carka = 0;
   int pomlcka = 0;
   int mod = 0;
   int pozice = 0;
   char cislo[CISLO];
   int typprekladu = 0;
   char addres[BUF];
   memset(cislo, '\0', sizeof(cislo));
   int *polept;

   for(int i = 0; i < argc; i++)
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
         polept = (int*)malloc(carka * sizeof(int));//nezapomenout uvolnit
         polept[0] = mod;
         polept[1] = carka;
         pomlcka = 0;
         //naplneni pole, cisl
         if( mod == 1 )
         {  //kontrola rozsahu velikosti portu
            if( atoi(argv[i+1]) > 0 && atoi(argv[i+1]) <= 65535 )
            {
               polept[2] = atoi(argv[i+1]);
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
                     polept[pozice2] = atoi(cislo);//ulozeni cisla do pole
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
            polept[pozice2] = atoi(cislo);//ulozeni posldeniho cisla do pole
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
                     polept[2] = atoi(cislo);
                     pozice1 = 0;
                     memset(cislo, '\0', sizeof(cislo));
                     pomlcka++;
                  }
                  else if( pomlcka == 1)
                  {
                     printf("pomlcka ----------%d-\n",atoi(cislo));
   
                     polept[3] = atoi(cislo);
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
               polept[3] = atoi(cislo);
            }
         }
         else  //nemelo by nastat
         {
            printf("neocekavana chyba, pokracujte smela dal :) \n");
         } 




         i++;
      }
      else if( (argv[i][0] == '-') && (argv[i][2] == 'u')
                                   && (argv[i][1] == 'p')
             ) 
      {
         //zpracovani FCE PU----------SPUSTI SE FCE PU


         //zpracovani portu ARGPU
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
            typprekladu = 1;
            for( int k = 0; argv[i][k] != '\0'; k++ )
            {
               addres[k] = argv[i][k];
            }
         }
         else
         {
            //adresa ve forme IP
            typprekladu = 2;
            for( int k =0; argv[i][k] != '\0'; k++ )
            {
               addres[k] = argv[i][k];
            }
         }
      }

   }
////////////////////////////////////
///kontrolni vypisy
         printf("carka %d \n",carka);
         for(int i = 0; i <  carka; i++)
         {
            printf("pole portu  %d\n",polept[i]);
         }

} 

////////////////////////////////////
//// kontrolni soucet
///////////////////////////////////
unsigned short checksum( unsigned short *datagram, int nwords ) {
   unsigned long sum;
   for( sum = 0; nwords > 0; nwords-- ) sum += *datagram++;
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   return ~sum;
}
////////////////////////////////////


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
////  naplneni struktury TCP hlavicky
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
   ip_head->ip_src.s_addr = inet_addr("128.0.0.1");//doplnit IP adresu
   ip_head->ip_dst.s_addr = sin.sin_addr.s_addr;

}

///////////////////////////////////////////////////////
////  naplneni struktoy TCP hlavicky
////////////////
//
void fillTCP(struct tcphdr* tcp_head) {

   tcp_head->th_sport = htons(1234);   //doplnit cilso portu
   tcp_head->th_dport = htons(1234);   //doplnit port
   tcp_head->th_seq = random();
   tcp_head->th_ack = 0;
   tcp_head->th_x2 = 0;
   tcp_head->th_off = 0;
   tcp_head->th_flags = TH_SYN;
   tcp_head->th_win = htonl(65535);
   tcp_head->th_sum = 0;
   tcp_head->th_urp = 0;
}


///////////////////////////////
///   main
///////////////////////////////
int main( int argc, char *argv[] ) {

   TArgum params;
printf("main\n");
   parserArg(argc, argv, params);//volani FCE pro argumenty
printf("end \n");

   char datagram[4096];//bufer, obsahuje IP hlavicku a TCP hlavicku
   
   int mSocket;
   openSocket( &mSocket);
   struct ip *ip_head = (struct ip *) datagram; // IP hlavika 
   struct tcphdr *tcp_head = (struct tcphdr *) ( datagram + sizeof( struct ip) );   // TCP hlavicka
   struct sockaddr_in sin;
   sin.sin_family = AF_INET;
   sin.sin_addr.s_addr = inet_addr("127.0.0.1");
   sin.sin_port = htons(50440);
   memset( datagram, 0, 4096);   // vynulovani datagramu

   fillIP(ip_head, sin);
   fillTCP(tcp_head);
   printf("tcp %d \n",ip_head->ip_sum);
   return 1;
}
