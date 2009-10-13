//xsendl00
//ISA
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
  /*    else if( (argv[i][0] == '-') && (argv[i][2] == 'u')
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
      }
*/
   }
////////////////////////////////////
///kontrolni vypisy
         printf("carka %d \n",carka);
         for(int i = 0; i <  carka; i++)
         {
            printf("pole portu  %d\n",polept[i]);
         }

} 


///////////////////////////////
///   main
///////////////////////////////
int main (int argc, char *argv[]) {

   TArgum params;
printf("main\n");
   parserArg(argc, argv, params);//volani FCE pro argumenty
printf("end \n");
   return 1;
}
