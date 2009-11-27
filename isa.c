////xsendl00
//ISA

#define __USE_BSD
#define __FAVOR_BSD
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
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

#include <net/if_dl.h>
#include <ifaddrs.h>
#include <errno.h>

extern int errno;
 
using namespace std;
#define BUF 100
#define ROZ 3 
#define CISLO 10 

#define MIN(X,Y) ( (X) < (Y) ? (X) : (Y) )
#define MAX(X,Y) ( (X) > (Y) ? (X) : (Y) )

#define PORT 8234 // cilso zdrojoveho portu
#define IP2 ("192.168.2.100")


/**
 * Struktura parametru
 */
typedef struct argument {
   unsigned short pt;   // aktivni v 1 
   unsigned short pu;   // aktivni v 1
   unsigned short typ_prekladu;  // 1 domain name, 2 IP
   int *polept;
   char rozhrani[ROZ];   // 1 = em0; 2 = ...
   char hostname_ip[BUF];
   char addres[BUF];
   struct sockaddr_in *src_addr; //zdrojova IP adresa
}  TArgum;


/**
 * Pomocna TCP header pro generovani kontrolniho souctu
 */
struct pom_tcp_head {
   u_int32_t p_src;
   u_int32_t p_dst;
   u_int8_t p_pad;
   u_int8_t p_protocol;
   u_int16_t p_tcplen;
};
  
 
/**
 * Parsrovani argumentu
 *
 * @param argc
 * @param *argv[]
 * @param &params
 */
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
   // kontrola napovedy
   if( argc == 2 )
   {
      if( (argv[1][0] == '-' && argv[1][2]=='e'
                && argv[1][1] == 'h' && argv[1][3]=='l' && argv[1][4]=='p')
                || (argv[1][0] == '-' && argv[1][1] == 'H'
                && argv[1][2] == 'E' && argv[1][3] == 'L'
                && argv[1][4] == 'P') )
      {  //obsah napovedy
         fprintf(stderr, "help\n");
         exit(-1);
      }
      else
      {
         fprintf(stderr, "Pro napovedu pouzijte prepinac -help nebo -HELP\n");
         exit(-1);
      }
   }
   // kontrola minimalniho poctu argimentu
   if( argc < 6 )
   {
      fprintf(stderr, "Spatny pocet argumentu\n");
      exit(-1);
   }

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
                     exit(-1);
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
                  exit(-1);
               }
            }
         }
         else
         {
            fprintf(stderr, "Spatne zadane parametry, po '-pt' musi nasledovat vycet portu a to ve tvaru\nPORT, nebo PORT,PORT,PORT a nebo PORT-PORT\n");
            exit(-1);
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
               exit(-1);
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
                     exit(-1);
                  }
                  pozice1 = 0;
                  memset(cislo, '\0', sizeof(cislo));
               }
               else
               {
                  fprintf(stderr, "MOD2 neni vyresena drivejsi kontrola\n");
                  exit(-1);
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
                     params.polept[3] = atoi(cislo);
                     pomlcka = 2;
                    // memset(cislo, '\0', sizeof(cislo));
                  }
                  //break;
                  //memset(cislo, '\0', sizeof(cislo));
               }
               else//nemuze nastat
               {
                  printf("nemelo nikdy nastat\n");
                  exit(-1);
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
            exit(-1);
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
         memset(params.rozhrani, '\0', sizeof(params.rozhrani));
         for( int l = 0; argv[i+1][l] != '\0'; l++ )
            params.rozhrani[l]=argv[i+1][l];
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
         }
      }

   }
} 


/**
 * Vypocet kontrolniho souctu
 *
 * @param[in] *buf 
 * @param[in] nwords
 * @return    sum
 */
int checkSum( unsigned short *buf, int nwords ) {
   unsigned long sum;

   for( sum = 0; nwords > 0; nwords-- )
   {
      sum += *buf++;
   }
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   return ~sum;
}


/**
 * Vytvoreni socketu
 *
 * @param[out] *mSocket Ukazatel na vytvoreny socket.
 * @return     error    Obsahuje chybu.
 */
int openSocket( int *mSocket) {

   int error = 0;
   
   // otevreni socketu
   if( (*mSocket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP) ) < 0 )
   {
      error = -1;
      return error;
   }

   int one = 1;
   const int *val = &one;
   if( setsockopt(*mSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
   {
      error = -2;
      return error;
   }

   return error;
}


/**
 * Naplneni IP hlavicky
 *
 * @param[out] ip_head Naplneni hlavicky potrepbe pro odeslani paketu
 * @param[in]  sin     Struktura obsahuji cilouvou IP adresu
 * @param[in]  params  Struktura obsahujici polozku zdrojove IP adresy
 */

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
void  fillIP(struct ip* ip_head, struct sockaddr_in sin, TArgum params) {

   ip_head->ip_hl = 5;  // velikost hlavicky (typisky 20 bytu)
   ip_head->ip_v = 4;   // verze IP protokolu
   ip_head->ip_tos = 0;
   ip_head->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
   ip_head->ip_id = htonl(54321);
   ip_head->ip_off= 0;//5
   ip_head->ip_ttl = 255;
   ip_head->ip_p = 6;   //IPPROTO_TCP
   ip_head->ip_sum = 0; //prozatim nula, po vypoctu se doplni
   ip_head->ip_src.s_addr = inet_addr(inet_ntoa(params.src_addr->sin_addr));
   ip_head->ip_dst.s_addr = sin.sin_addr.s_addr;
}


/**
 * Naplneni struktury TCP hlavicky
 *
 * @param[out] tcp_head Struktura, potreban pro odeslani paketu 
 * @param[in]  i        Cislo aktualne prohledavaneho portu
 */
void fillTCP( struct tcphdr* tcp_head, int i ) {
   
   tcp_head->th_sport = htons(PORT);   //cilso portu(zdrojovy)
   tcp_head->th_dport = htons(i);   //cilovy port
   tcp_head->th_seq = random();
   tcp_head->th_ack = 0;
   tcp_head->th_x2 = 0;
   tcp_head->th_off = 5;//0;
   tcp_head->th_flags = TH_SYN;
   tcp_head->th_win = htonl(65535);
   tcp_head->th_urp = 0;
}


/**
 * Zjisteni IP adresy pozadovaneho interface
 *
 * @param[out] params Struktura obsahujici nazev interface a budouci IP SRC
 * @return     error  Stav o chybe.
 */
int ipInterface( TArgum &params ) {

   int error = 1;
   pcap_if_t *device;

   char *errbuf;
   pcap_findalldevs(&device, errbuf);
   pcap_addr_t *adresa;

   bool found = 0;
// najdeme v seznamu pozadovane rozhrani
   while( found == 0 )
   {
      if( strcmp( device->name, params.rozhrani) == 0 )
      {
         adresa = device->addresses;
         found = 1;
      }
      if(device->next == NULL && strcmp( device->name, params.rozhrani) != 0)
      { 
         error = -1;
         return error;
      }
      device = device->next;  // dalsi zarizeni
   }
   found = 0;
   for(; found != 1; adresa = adresa->next )
   {
      params.src_addr=(struct sockaddr_in *)(adresa->addr);
      if(adresa->addr->sa_family == AF_INET)
      {
         found = 1;
        // printf("IPadres%s\n", inet_ntoa(params.src_addr->sin_addr));
      }
      
      if(adresa->next == NULL && adresa->addr->sa_family != AF_INET)
      {
         error = -2;
         return error;
      }
   }
   pcap_freealldevs(device);

   return error;
}
      

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {


printf("ve fci pro rozbor prijatyh dat\n");

printf("cas paketu :%s\n", ctime((const time_t *)&((header->ts.tv_sec))));
   struct ether_header *ethh;
   struct ip *iph;
   struct tcphdr *tcph;
   //struct u_char *payload;

   iph = (struct ip *)(pkt_data + sizeof(struct ether_header));
   int iplen = iph->ip_hl*4;
   
   tcph = (struct tcphdr *)(pkt_data + sizeof(struct ether_header)+iplen);
//printf( "tcp-h_flagf : %s\n", tcph->th_flags);
   if( tcph->th_flags == 0x14 )
      printf("je to doma\n");
   else
      printf("nekde chyba\n");
}

///////////////////////////////////////////////////////////
///   main
//////////////////////////////////////////////////////////
int main( int argc, char *argv[] ) {

   int error;
   TArgum params;
   memset(params.rozhrani, '\0', sizeof(params.rozhrani));
   parserArg(argc, argv, params);   // volani FCE pro argumenty
   if( (error = ipInterface( params )) != 1 )
   {
      switch( error ) {
         case -1: fprintf(stderr, "CHYBA pri hledani IP adresy zarizeni %s, toto zarizeni na vasem PC neexistuje!\n", params.rozhrani);
                  exit(-1);
                  break;
         case -2: fprintf(stderr, "CHYBA pri hledani IP adresy zarizeni %s, toto zarizeni nema adresu typy AF_INET\n", params.rozhrani);
         default: break;
      }
   }

   int mSocket;
   if( (error = openSocket( &mSocket )) != 1)
   {
      switch( error ) {
         case -1: fprintf(stderr, "CHYBA pri vytvareni socketu\n");
                  exit(-1);
                  break;
         case -2: fprintf(stderr, "CHYBA pri inicializaci socketu\n");
                  exit(-1);
                  break;
         default: break;
      }
   }

   if( params.pt == 1 )  // TCP scanning
   {
      char datagram[4096]; // bufer, obsahuje IP hlavicku a TCP hlavicku
   
      struct ip *ip_head = (struct ip *) datagram; // IP hlavika 
      struct tcphdr *tcp_head = (struct tcphdr *) ( datagram + sizeof( struct ip) );   // TCP hlavicka
      struct sockaddr_in sin; //struktur apro vzdalene PC
      memset(&sin, '\0', sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = inet_addr(IP2);   //asik ma byt 128.0.0.1
      memset( datagram, 0, 4096);   // vynulovani datagramu

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

//////////////////

            fillTCP(tcp_head, params.polept[i]);// naplneni TCP hlavicky
   struct pom_tcp_head *pseudo = (struct pom_tcp_head *)((char*)tcp_head - sizeof(struct pom_tcp_head));
   pseudo->p_src = inet_addr(inet_ntoa(params.src_addr->sin_addr));//inet_addr("192.168.2.102");
   pseudo->p_dst = inet_addr(IP2);
   pseudo->p_protocol = IPPROTO_TCP;
   pseudo->p_tcplen = htons(sizeof(struct tcphdr));

   tcp_head->th_sum = checkSum((u_short*)pseudo, sizeof(struct pom_tcp_head)+sizeof(struct tcphdr)); 

            sin.sin_port = htons(params.polept[i]);
            fillIP(ip_head, sin, params);     // naplneni IP hlavicky
            ip_head->ip_sum = checkSum( (unsigned short *)datagram, ip_head->ip_len >> 1);
//send packet
            if( sendto(mSocket, datagram, ip_head->ip_len, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0 )
            {
               cerr<<  strerror(errno)<<endl;  
            }
            else
            {
////////////////////////////////
/////////zachytavani paketu



   //pcap_if_t *device;
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp; //zkompilovany filtr
bpf_u_int32 net;  //OUR IP
handle = pcap_open_live(params.rozhrani, BUFSIZ, 1, 1000, errbuf);
if( handle == NULL )
{
   printf("chyba u pcap open %s:%s\n",params.rozhrani, errbuf);
   pcap_freealldevs((pcap_if_t *)handle);
}

// compile filter
char filter[] = "tcp[0:2]=8000 && tcp[2:2]=8234";// && ip[16:4]=192.168.2.102";// && tcp port 8000 || tcp port 8234";

if( pcap_compile(handle, &fp, filter, 0, net) == -1 )
{
   printf("chyba pri kompilaci filtru pro achyvani paketu \n");
}
// nastaveni filtru
if( pcap_setfilter(handle, &fp) == -1 )
{
   printf("chyba pri nastavovani fitlru\n");
}

//start capture
printf("zacatek zachytavani\n");
pcap_dispatch(handle, 1, packet_handler, NULL);
//pcap_loop(handle, 0, packet_handler, NULL);
printf("konec zachytavani\n");

pcap_close(handle);
//pcap_free(&fp);
//////////
            }
}
      }
   }
   if( params.pu == 1 ) // UDP scanning
   {

   }
   return 1;
}
