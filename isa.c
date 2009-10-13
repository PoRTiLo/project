//xsendl00
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
//volat FCEEEEEEEEEEEEEEEE PT
printf("fce PT ,\n");
         //zpracovani portu ARGPT
//kontrola zda je zadany spravny port,jako v rozsahu a zda tam neni pismeno
         for( pozice = 0; (argv[i+1][pozice] != '\0');
              pozice++ )
         {
            if( argv[i+1][pozice] == ',' )//obsahuje carku
            {     //mod 2, pole velikost podle postu carek +2
printf("carka\n");
               mod = 2;
               carka++;
            }
//pozor na prvni znak -------
            else if( argv[i+1][pozice] == '-' )//obsahuje '-'
            {     //mod 3, pole velikost 4
printf("----\n");
               mod = 3;
               carka = 4;
            }
//dodelat,poresit co nastane kdyz spatne zadany port
            else//neni cislo
            {
//printf("neni cislo \n");
            }
         }
      
         if( mod == 0 )
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
         //naplneni pole, cisl
         if( mod == 1 )
         {
            polept[2] = atoi(argv[i+1]);
         }
         else if( mod == 2 )
         {
            for( pozice = 0; argv[i+1][pozice] != '\0'; pozice++ )
            {
printf("ve for mode 2\n");
               if( isdigit(argv[i+1][pozice]) != 0 )
               {
                  cislo[pozice1] = argv[i+1][pozice];
                  pozice1++;
               }
               else if( argv[i+1][pozice] == ',' )
               {
                  polept[pozice2] = atoi(cislo);
                  pozice2++;
                  pozice1 = 0;
                  memset(cislo, '\0', sizeof(cislo));
               }
               else
               {
                  printf("nemelo niukdy nastat\n");
               }
            }
printf("co\n");
            polept[pozice2] = atoi(cislo);
         }
         else if( mod == 3 )
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
                  polept[2] = atoi(cislo);
                  pozice1 = 0;
                  memset(cislo, '\0', sizeof(cislo));
               }
               else//nemuze nastat
               {
                  printf("nemelo nastat\n");
               }
            }
            polept[3] = atoi(cislo);
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
