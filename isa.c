/**
 *
 * ISA - Jednoduchy TCP/UDP scanner
 *
 * Jaroslav Sendler, xsendl00
 * mailto:xsendl00@stud.fit.vutbr.cz
 *
 */



/**
 * TODO: dodelat filter aby se sam zmenil po zmene zdrojoveho portu 
 *       poresit UDP, proc je tal divne
 *       dokumnetace
 *       sbalit, odevzdat DNES
 */



#define __USE_BSD
#define __FAVOR_BSD
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
//#include <string>
//#include <string.h>
#include <ctype.h>
#include <netdb.h>
//#include <iostream>
//#include <fstream>
#include <set>
//#include <cstring>
#include <arpa/inet.h>
//#include <sstream>
#include "pcap.h"
//#include <net/if_dl.h>
//#include <ifaddrs.h>
#include <errno.h>

extern int errno;
 
using namespace std;
#define BUF 100   // pomocny vel buffer
#define ROZ 3     // velikost pro pole obsahujici pracujici rozhrani 
#define CISLO 10  // pomocny vel buffer

#define MIN(X,Y) ( (X) < (Y) ? (X) : (Y) )
#define MAX(X,Y) ( (X) > (Y) ? (X) : (Y) )

#define PORT 8234 // cilso zdrojoveho portu

#define TIME 1000 // spozdeni nacitani prichozich paketu pro TCP scanning
#define TIME1 5000 // spozdeni nacitani prichozich paketu pro UDP scanning 

#define HELP "\n\nNapoveda : Jednoduchy TCP/UDP scanner\nversion : 1.00, Jaroslav Sendler, xsendl00\nmailto : xsendl00@stud.fit.vutbr.cz\n\nProgram slouzi pro skenovani portu pomoci TCP nebo UDP.\nMa nektere povinne prepinace(4)\n-pt  <cislo> skenovani TCP\n-pu  <cislo> skenovani UDP\n-i   <rozhrani> nazev rozhrani pro skenovani\n[IP adresa | domenove jmeno]\n<cislo> cislo portu mozno zadat, vyctem, nebo rozsahem\n\n"



/**
 * Struktura parametru
 */
typedef struct argument {
   unsigned short pt;   // aktivni v 1 
   unsigned short pu;   // aktivni v 1
   unsigned short sizePT;
   unsigned short sizePU;
   int *polept;
   int *polepu;
   char rozhrani[ROZ];   // 1 = em0; 2 = ...
   char hostname_ip[BUF];
   struct sockaddr_in *src_addr; // zdrojova IP adresa
   struct in_addr ipv4;
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
 * Pomocna UDP header pro generovani kontrolniho souctu
 */ 
struct pom_udp_head {
   u_int32_t p_src;
   u_int32_t p_dst;
   u_int16_t p_udplen;
   u_int16_t p_protocol;
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
   params.pt = 0;
   params.pu = 0;

   int carka = 0;
   int pomlcka = 0;
   int mod = 0;
   int pozice = 0;
   char cislo[CISLO];
   memset(cislo, '\0', sizeof(cislo));
   // kontrola napovedy
   if( argc == 2 )
   {
      if( (argv[1][0] == '-' && argv[1][2]=='e'
                && argv[1][1] == 'h' && argv[1][3]=='l' && argv[1][4]=='p')
                || (argv[1][0] == '-' && argv[1][1] == 'H'
                && argv[1][2] == 'E' && argv[1][3] == 'L'
                && argv[1][4] == 'P') )
      {  //obsah napovedy
         fprintf(stderr, HELP );
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
         else if( mod == 2 )
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
                  if( pomlcka == 0 )
                  {
                     params.polept[2] = atoi(cislo);
                     pozice1 = 0;
                     memset(cislo, '\0', sizeof(cislo));
                     pomlcka++;
                  }
                  else if( pomlcka == 1 )
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
                  fprintf(stderr, "nemelo nikdy nastat\n");
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
            fprintf(stderr, "neocekavana chyba, pokracujte smela dal :) \n");
            exit(-1);
         } 

         i++;
         params.pt = 1;
         params.sizePT=0;
         for(int pt = 0; params.polept[pt] != '\0'; pt++)
            params.sizePT++;
      }
      else if( (argv[i][0] == '-') && (argv[i][2] == 'u')
                                   && (argv[i][1] == 'p')
             ) 
      {
         carka = 0;
         pomlcka = 0;
         mod = 0;
         pozice = 0;
         memset(cislo, '\0', sizeof(cislo));
         //zpracovani FCE PU----------SPUSTI SE FCE PU

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
         params.polepu = (int*)malloc(carka * sizeof(int));//nezapomenout uvolnit
         memset(params.polepu, '\0', sizeof(params.polepu));
         params.polepu[0] = mod;
         params.polepu[1] = carka;
         pomlcka = 0;
         //naplneni pole, cisl
         if( mod == 1 )
         {  //kontrola rozsahu velikosti portu
            if( atoi(argv[i+1]) > 0 && atoi(argv[i+1]) <= 65535 )
            {
              params.polepu[2] = atoi(argv[i+1]);
            }
            else //vytvorit fci na vypis chyb
            {
               fprintf(stderr, "CHYBA MOD1 spatne rozsah portu\n");
               exit(-1);
            }
         }
         else if( mod == 2 )  // porty zadany vyctem
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
                     params.polepu[pozice2] = atoi(cislo);//ulozeni cisla do pole
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
            params.polepu[pozice2] = atoi(cislo);//ulozeni posldeniho cisla do pole
         }
         // pracuje tak ze vezme jen dobrou cast z portu
         else if( mod == 3 )  // mod rozsah portu
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
                     params.polepu[2] = atoi(cislo);
                     pozice1 = 0;
                     memset(cislo, '\0', sizeof(cislo));
                     pomlcka++;
                  }
                  else if( pomlcka == 1)
                  {
                     params.polepu[3] = atoi(cislo);
                     pomlcka = 2;
                  }
               }
               else//nemuze nastat
               {
                  printf("nemelo nikdy nastat\n");
                  exit(-1);
               }
            }
            if( pomlcka == 1 )
            {
               params.polepu[3] = atoi(cislo);
            }
         }
         else  //nemelo by nastat
         {
            fprintf(stderr, "neocekavana chyba, pokracujte smela dal :) \n");
            exit(-1);
         } 

         i++;
         params.pu = 1; // skenovani UDP je aktivni
         params.sizePU=0;
         for(int pu = 0; params.polepu[pu] != '\0'; pu++)
            params.sizePU++;
      }
      else if( argv[i][0] == '-' && argv[i][1] == 'i' )   //rozhrani
      {
         memset(params.rozhrani, '\0', sizeof(params.rozhrani));
         for( int l = 0; argv[i+1][l] != '\0'; l++ )
            params.rozhrani[l] = argv[i+1][l];
         i++;
      }
      else if( argv[i][0] == '-')
      {
         fprintf(stderr, "Chybny parametr\n");
         exit(-1);
      }
      else
      {
         //zpracovani IP adresy nebo domain name
         if( isdigit(argv[i][0]) == 0 ) // domain name
         {
            struct hostent *remoteHost = gethostbyname(argv[i]);
            if( remoteHost == NULL )
            {
               fprintf(stderr, "Spatne zadane domenove jmeno\n");
               exit(-1);
            }
            params.ipv4.s_addr=*(u_long *)remoteHost->h_addr_list[0];
         }
         else // IP adresa
         {
            params.ipv4.s_addr = inet_addr(argv[i]);
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
 * @param[i]   typ      Typ posilaneho paketu TCP/UDP
 * @return     error    Obsahuje chybu.
 */
int openSocket( int *mSocket, int typ ) {

   int error = 0;
   
   // otevreni socketu
   if( typ == 1 ) // TCP
   {   
      if( (*mSocket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP) ) < 0 )
      {
         error = -1;
         return error;
      }
   }
   else  // otevreni UDP socketu
   {
      if( (*mSocket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP) ) < 0 )
      {
         error = -1;
         return error;
      } 
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
void  fillIP( struct ip* ip_head, struct sockaddr_in sin, TArgum params ) {

   ip_head->ip_hl = 5;  // velikost hlavicky (typisky 20 bytu)
   ip_head->ip_v = 4;   // verze IP protokolu
   ip_head->ip_tos = 0;
   ip_head->ip_len = sizeof( struct ip ) + sizeof( struct tcphdr );
   ip_head->ip_id = htonl( 54321 );
   ip_head->ip_off= 0;//5
   ip_head->ip_ttl = 255;
   ip_head->ip_p = 6;   //IPPROTO_TCP
   ip_head->ip_sum = 0; //prozatim nula, po vypoctu se doplni
   ip_head->ip_src.s_addr = inet_addr( inet_ntoa(params.src_addr->sin_addr) );
   ip_head->ip_dst.s_addr = sin.sin_addr.s_addr;
}


/**
 * Naplneni IP hlavicky pro pakety UDP
 *
 * @param[out] ipheadUDP
 * @param[in]  din
 * @param[in]  sin
 */
void fillIPudp( struct ip* ip_headUDP, struct sockaddr_in din, struct sockaddr_in sin ) {

   ip_headUDP->ip_hl = 5;  // velikost hlavicky (typisky 20 bytu)
   ip_headUDP->ip_v = 4;   // verze IP protokolu
   ip_headUDP->ip_tos = 16;
   ip_headUDP->ip_len = sizeof( struct ip ) + sizeof( struct udphdr );
   ip_headUDP->ip_id = htonl( 54321 );
   ip_headUDP->ip_off= 0;//5
   ip_headUDP->ip_ttl = 255;
   ip_headUDP->ip_p = 17;   //IPPROTO_UDP
   ip_headUDP->ip_sum = 0; //prozatim nula, po vypoctu se doplni
   ip_headUDP->ip_src.s_addr = sin.sin_addr.s_addr;
   ip_headUDP->ip_dst.s_addr = din.sin_addr.s_addr;
}


/**
 * Naplneni struktury TCP hlavicky
 *
 * @param[out] tcp_head Struktura, potreban pro odeslani paketu 
 * @param[in]  i        Cislo aktualne prohledavaneho portu
 */
void fillTCP( struct tcphdr* tcp_head, int i ) {
   
   tcp_head->th_sport = htons( PORT );   //cilso portu(zdrojovy)
   tcp_head->th_dport = htons( i );   //cilovy port
   tcp_head->th_seq = random();
   tcp_head->th_ack = 0;
   tcp_head->th_x2 = 0;
   tcp_head->th_off = 5;//0;
   tcp_head->th_flags = TH_SYN;
   tcp_head->th_win = htonl( 65535 );
   tcp_head->th_urp = 0;
}


/**
 * Naplneni struktury UDP hlavicky
 *
 * @param[out] udp_head Struktura potrebna pro odeslani paketu
 * @param[in]  i        Cislo aktualne prohledavaneho portu
 */
void fillUDP( struct udphdr* udp_head, int i ) {

   udp_head->uh_sport = htons( PORT ); // zdrojovy port
   udp_head->uh_dport = htons( i ); // cilovy port
   udp_head->uh_ulen = htons( sizeof(struct udphdr) );   // velikost
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
      if( strcmp( device->name, params.rozhrani) == 0 ) // zar. nalezeno
      {
         adresa = device->addresses;
         found = 1;
      }
      if( device->next == NULL && strcmp( device->name, params.rozhrani) != 0 ) // posledni zarizeni v seznamu a neni to hledane zarizeni
      { 
         error = -1;
         return error;
      }
      device = device->next;  // dalsi zarizeni
   }
   found = 0;
   for( ; found != 1; adresa = adresa->next )   // prochazeni seznamu adres daneho zarizeni
   {
      params.src_addr=(struct sockaddr_in *)(adresa->addr);
      if( adresa->addr->sa_family == AF_INET )  // nalezena IPv4 adresa
      {
         found = 1;  
      }
      // jsme na poslednim prvku seznamu a adresa IPV4 tam neni 
      if( adresa->next == NULL && adresa->addr->sa_family != AF_INET )
      {
         error = -2;
         return error;
      }
   }
   pcap_freealldevs(device);  // uvolneni

   return error;
}


/**
 * Zjisteni obsahu chyceneho paketu jako odpoved na UDP paket
 *
 * @param[in] *param
 * @param[in] *head
 * @param[in] *pkt_data
 */      
void packet_handlerUDP( u_char *param, const struct pcap_pkthdr *head, const u_char *pkt_data) {

   // pomocne struktury
   struct ip *iph;
   struct icmphdr *icmph;
   // preskoceni ethernet hlavicky
   iph = (struct ip *)(pkt_data + sizeof(struct ether_header));
   int iplen = iph->ip_hl*4;  // delka hlavicky IP
   // preskoceni IP hlavicky
   icmph = (struct icmphdr *)(pkt_data + sizeof(struct ether_header)+iplen);

   if( icmph->icmp_type == 3 )
      fprintf(stdout, " closed");
   else
      fprintf(stdout, " open");
     
}


/**
 * Zjisteni obsahu chyceneho paketu jako odpoved na TCP paket
 *
 * @param[in] *param
 * @param[in] *head
 * @param[in] *pkt_data
 */      
void packet_handlerTCP(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {

   // pomocne struktury
   struct ip *iph;
   struct tcphdr *tcph;

   // preskoceni ethernet hlavicky
   iph = (struct ip *)(pkt_data + sizeof(struct ether_header));
   int iplen = iph->ip_hl*4;
   
   // preskoceni IP hlavicky
   tcph = (struct tcphdr *)(pkt_data + sizeof(struct ether_header)+iplen);

   if( tcph->th_flags == 0x14 )
      fprintf(stdout," closed");
   else
      fprintf(stdout," open");
}


/**
 * MAIN
 *
 * @param[in] argc
 * @param[in] **argv[]
 * @return
 */

int main( int argc, char *argv[] ) {

   int error;
   int mSocket;
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
   char datagram[4096]; // bufer, obsahuje IP hlavicku a TCP hlavicku
 
   struct ip *ip_head = (struct ip *) datagram; // IP hlavika 
   struct tcphdr *tcp_head = (struct tcphdr *) ( datagram + sizeof( struct ip) );   // TCP hlavicka
   struct sockaddr_in sin, din; //struktura pro vzdalene PC
   memset(&sin, '\0', sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_addr.s_addr = params.ipv4.s_addr;

   memset( datagram, 0, 4096);   // vynulovani datagramu

   if( params.pt == 1 )  // TCP scanning
   {
      int typ = 1;
      if( (error = openSocket( &mSocket, typ )) != 1)
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

      if(params.polept[0] == 3)  //nastaveni MAx, MIN portu u rozsahu
      {
         int max = MAX(params.polept[2], params.polept[3]);
         int min = MIN(params.polept[2], params.polept[3]);
         params.polept[2] = min;
         params.polept[3] = max;
      }
      params.polept[params.sizePT] = '\0';
      int znovu = 1;
      for(int i = 2; params.polept[i] != '\0'; i++)
      {
         memset(datagram, '\0', sizeof(datagram));
         if(params.polept[0] == 3)  //porty zadany pomoci rozsahu
         {
            for( int l = params.polept[2]; l <= params.polept[3]; l++)
            {
               memset(datagram, '\0', sizeof(datagram));
               fillTCP(tcp_head, l);// naplneni TCP hlavicky
               struct pom_tcp_head *pseudo = (struct pom_tcp_head *)((char*)tcp_head - sizeof(struct pom_tcp_head));
               pseudo->p_src = inet_addr(inet_ntoa(params.src_addr->sin_addr));
               pseudo->p_dst = params.ipv4.s_addr;
               pseudo->p_protocol = IPPROTO_TCP;
               pseudo->p_tcplen = htons(sizeof(struct tcphdr));

               tcp_head->th_sum = checkSum((u_short*)pseudo, sizeof(struct pom_tcp_head)+sizeof(struct tcphdr)); 

               sin.sin_port = htons(l);
               fillIP(ip_head, sin, params);     // naplneni IP hlavicky
               ip_head->ip_sum = checkSum( (unsigned short *)datagram, ip_head->ip_len >> 1);
               //send packet
               if( sendto(mSocket, datagram, ip_head->ip_len, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0 )
               {
                  strerror(errno);  
                  exit(-1);
               }
               else
               {
               /////////zachytavani paketu
                  pcap_t *handle;
                  char errbuf[PCAP_ERRBUF_SIZE];
                  struct bpf_program fp; //zkompilovany filtr
                  bpf_u_int32 net;  //OUR IP
                  handle = pcap_open_live(params.rozhrani, BUFSIZ, 1, TIME, errbuf);
                  if( handle == NULL )
                  {
                     fprintf(stderr, "chyba u pcap open %s:%s\n",params.rozhrani, errbuf);
                     pcap_freealldevs((pcap_if_t *)handle);
                     exit(-1);
                  }

                  // compile filter
                  char d_port[10];
                  sprintf(d_port, "%d",l);
                  char filter[] = "tcp[2:2]=8234 && tcp[0:2]=";
                  strcat( filter, d_port);
                  if( pcap_compile(handle, &fp, filter, 0, net) == -1 )
                  {
                     fprintf(stderr, "chyba pri kompilaci filtru pro achyvani paketu \n");
                     exit(-1);
                  }
                  // nastaveni filtru
                  if( pcap_setfilter(handle, &fp) == -1 )
                  {
                     fprintf(stderr, "chyba pri nastavovani filtru\n");
                     exit(-1);
                  }

                  //start capture
                  if( znovu == 1 )
                     fprintf(stdout,"%d/tcp",l);
                  if( pcap_dispatch(handle, 1, packet_handlerTCP, NULL) == 0 )
                  {
                     if( znovu == 1 )
                     {
                        l--;
                        znovu = 0;
                     }
                     else
                     {
                        fprintf(stdout, " filtered");
                        znovu = 1;
                     }
                  }
                  if( znovu == 1 )
                     fprintf(stdout, "\n");
                  pcap_close(handle);
               }
            }
            i++;
            break;
         }
         else  // cilso portu zadane vyctem nebo cislem
         {
            fillTCP(tcp_head, params.polept[i]);// naplneni TCP hlavicky
            struct pom_tcp_head *pseudo = (struct pom_tcp_head *)((char*)tcp_head - sizeof(struct pom_tcp_head));
            pseudo->p_src = inet_addr(inet_ntoa(params.src_addr->sin_addr));
            pseudo->p_dst = params.ipv4.s_addr;
            pseudo->p_protocol = IPPROTO_TCP;
            pseudo->p_tcplen = htons(sizeof(struct tcphdr));

            tcp_head->th_sum = checkSum((u_short*)pseudo, sizeof(struct pom_tcp_head)+sizeof(struct tcphdr)); 

            sin.sin_port = htons(params.polept[i]);
            fillIP(ip_head, sin, params);     // naplneni IP hlavicky
            ip_head->ip_sum = checkSum( (unsigned short *)datagram, ip_head->ip_len >> 1);
            //send packet
            if( sendto(mSocket, datagram, ip_head->ip_len, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0 )
            {
               strerror(errno);  
               exit(-1);
            }
            else
            {
            /////////zachytavani paketu
               pcap_t *handle;
               char errbuf[PCAP_ERRBUF_SIZE];
               struct bpf_program fp; //zkompilovany filtr
               bpf_u_int32 net;  //OUR IP
               handle = pcap_open_live(params.rozhrani, BUFSIZ, 1, TIME, errbuf);
               if( handle == NULL )
               {
                  fprintf(stderr, "chyba u pcap open %s:%s\n",params.rozhrani, errbuf);
                  pcap_freealldevs((pcap_if_t *)handle);
                  exit(-1);
               }
               char d_port[10];
               sprintf(d_port, "%d",params.polept[i]);
               char filter[] = "tcp[2:2]=8234 && tcp[0:2]=";
               strcat( filter, d_port);
               if( pcap_compile(handle, &fp, filter, 0, net) == -1 )
               {
                  fprintf(stderr, "chyba pri kompilaci filtru pro achyvani paketu \n");
                  exit(-1);
               }
               // nastaveni filtru
               if( pcap_setfilter(handle, &fp) == -1 )
               {
                  fprintf(stderr, "chyba pri nastavovani fitlru\n");
                  exit(-1);
               }

               //start capture
               if( znovu == 1 )
                  fprintf(stdout,"%d/tcp",params.polept[i]);
               if( pcap_dispatch(handle, 1, packet_handlerTCP, NULL) == 0 )
               {
                  if( znovu == 1 )
                  {
                     i--;
                     znovu = 0;
                  }
                  else
                  {
                     fprintf(stdout, " filtered");
                     znovu = 1;
                  }
               }
               if( znovu == 1 )
                  fprintf(stdout, "\n");
               pcap_close(handle);
            }
         }
      }
   }
   if( params.pu == 1 ) // UDP scanning
   {
      struct udphdr *udp_head = (struct udphdr *)(datagram + sizeof(struct ip) );     
      struct ip *ip_headUDP = (struct ip *) datagram; // IP hlavika 
      int typ = 2;
      if( (error = openSocket( &mSocket, typ )) != 1)
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
      if(params.polepu[0] == 3)  //nastaveni MAx, MIN portu u rozsahu
      {
         int max = MAX(params.polepu[2], params.polepu[3]);
         int min = MIN(params.polepu[2], params.polepu[3]);
         params.polepu[2] = min;
         params.polepu[3] = max;
      }
      params.polepu[params.sizePU] = '\0';
      for(int i = 2; params.polepu[i] != '\0'; i++)
      {
         memset(datagram, '\0', sizeof(datagram));
         if(params.polepu[0] == 3)  //porty zadany pomoci rozsahu
         {
            for( int l = params.polepu[2]; l <= params.polepu[3]; l++)
            {
               memset(datagram, '\0', sizeof(datagram));
               fillUDP(udp_head, l);   // naplneni UDP hlavicky
               din.sin_port = htons(l);//cilovy port
               sin.sin_port = htons(PORT);
               din.sin_family = AF_INET;
               sin.sin_addr.s_addr = params.src_addr->sin_addr.s_addr;
               din.sin_addr.s_addr = params.ipv4.s_addr;

               struct pom_udp_head *pseudo = (struct pom_udp_head *)((char*)udp_head - sizeof(struct pom_udp_head));
               pseudo->p_src = htons(PORT);
               pseudo->p_dst = htons(l);
               pseudo->p_protocol = IPPROTO_UDP;
               pseudo->p_udplen = htons(sizeof(struct udphdr));

              // udp_head->uh_sum = checkSum((u_short*)pseudo, sizeof(struct pom_udp_head)+sizeof(struct udphdr)); 

               fillIPudp(ip_headUDP, din, sin);     // naplneni IP hlavicky
               ip_head->ip_sum = checkSum( (unsigned short *)datagram, ip_head->ip_len >> 1);
               //send packet
               if( sendto(mSocket, datagram, ip_head->ip_len, 0, (struct sockaddr *) &din, sizeof(din)) < 0 )
               {
                  strerror(errno);  
                  exit(-1);
               }
               else
               {
               /////////zachytavani paketu
                  pcap_t *handle;
                  char errbuf[PCAP_ERRBUF_SIZE];
                  struct bpf_program fp; //zkompilovany filtr
                  bpf_u_int32 net;  //OUR IP
                  handle = pcap_open_live(params.rozhrani, BUFSIZ, 1, TIME1, errbuf);
                  if( handle == NULL )
                  {
                     fprintf(stderr, "chyba u pcap open %s:%s\n",params.rozhrani, errbuf);
                     pcap_freealldevs((pcap_if_t *)handle);
                     exit(-1);
                  }

                  char d_port[10];
                  sprintf(d_port, "%d",l);
                  // compile filter
                  char filter[] = "icmp[28:2]=8234 && icmp[30:2]=";
                  strcat( filter, d_port );
                  if( pcap_compile(handle, &fp, filter, 0, net) == -1 )
                  {
                     fprintf(stderr, "chyba pri kompilaci filtru pro achyvani paketu \n");
                     exit(-1);
                  }
                  // nastaveni filtru
                  if( pcap_setfilter(handle, &fp) == -1 )
                  {
                     fprintf(stderr, "chyba pri nastavovani fitlru\n");
                     exit(-1);
                  }

                  //start capture
                  fprintf(stdout,"%d/udp",l);
                  if( pcap_dispatch(handle, 1, packet_handlerUDP, NULL) == 0 )
                     fprintf(stdout, " open");
                  fprintf(stdout, "\n");
                  pcap_close(handle);
                  //pcap_free(&fp);
               }
            }
            i++;
            break;
         }
         else  // cilso portu zadane vyctem nebo cislem
         {
            fillUDP(udp_head, params.polepu[i]);   // naplneni UDP hlavicky
            din.sin_port = htons(params.polepu[i]);//cilovy port
            sin.sin_port = htons(PORT);//zdrojovy port
            din.sin_family = AF_INET;
            sin.sin_addr.s_addr = params.src_addr->sin_addr.s_addr;
            din.sin_addr.s_addr = params.ipv4.s_addr;
            struct pom_udp_head *pseudo = (struct pom_udp_head *)((char*)udp_head - sizeof(struct pom_udp_head));
            pseudo->p_src = htons(PORT); 
            pseudo->p_dst = htons(params.polepu[i]);
            pseudo->p_protocol = IPPROTO_UDP;
            pseudo->p_udplen = htons(sizeof(struct udphdr));

           // udp_head->uh_sum = checkSum((u_short*)pseudo, sizeof(struct pom_udp_head)+sizeof(struct udphdr )); 

            fillIPudp(ip_headUDP, din, sin);     // naplneni IP hlavicky
            ip_head->ip_sum = checkSum( (unsigned short *)datagram, ip_head->ip_len >> 1);
            //send packet
            if( sendto(mSocket, datagram, ip_head->ip_len, 0, (struct sockaddr *) &din, sizeof(din)) < 0 )
            {
               strerror(errno);  
               exit(-1);
            }
            else
            {
            /////////zachytavani paketu
               pcap_t *handle;
               char errbuf[PCAP_ERRBUF_SIZE];
               struct bpf_program fp; //zkompilovany filtr
               bpf_u_int32 net;  //OUR IP
               handle = pcap_open_live(params.rozhrani, BUFSIZ, 1, TIME1, errbuf);
               if( handle == NULL )
               {
                  fprintf(stderr, "chyba u pcap open %s:%s\n",params.rozhrani, errbuf);
                  pcap_freealldevs((pcap_if_t *)handle);
               }
               char d_port[10];
               sprintf(d_port, "%d",params.polepu[i]);
               char filter[] = "icmp[28:2]=8234 && icmp[30:2]=";
               strcat( filter, d_port );
               // compile filter
               if( pcap_compile(handle, &fp, filter, 0, net) == -1 )
               {
                  fprintf(stderr, "chyba pri kompilaci filtru pro achyvani paketu \n");
                  exit(-1);
               }
               // nastaveni filtru
               if( pcap_setfilter(handle, &fp) == -1 )
               {
                  fprintf(stderr, "chyba pri nastavovani fitlru\n");
                  exit(-1);
               }

               //start capture
               fprintf(stdout,"%d/udp",params.polepu[i]);
               if( pcap_dispatch(handle, 1, packet_handlerUDP, NULL) == 0 )
                  fprintf(stdout," open");
               fprintf(stdout, "\n");
               pcap_close(handle);
            }
         }
      }
   }
   
   if( params.pu == 1 )
      free(params.polepu);
   if( params.pt == 1 )
      free(params.polept);
   close(mSocket);   // uzavreni socketu

   return 1;
}
