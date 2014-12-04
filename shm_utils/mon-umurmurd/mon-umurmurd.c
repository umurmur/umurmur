#include <fcntl.h> /* For O_* constants */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "../../src/sharedmemory.h"
#include "../../src/sharedmemory_global.h"

enum{ NOP_SHM, WAIT_ATTACH_SHM, TRY_ATTACH_SHM, MAT_SHM, CLEAN_UP_SHM, RUN_SHM };

int wait = 0, opt;
uint8_t last, shm_statem = TRY_ATTACH_SHM;

void run_shm(void);

int main(int argc, char **argv) 
{
  struct stat buf;
  int bindport = 0;
  
    while ( (opt = getopt(argc, argv, "wb:")) != -1 ) 
    {
        switch(opt) 
        {
           case 'w':
              wait = 1;
              break;
           case 'b':
              bindport = atoi(optarg);
              break;              
           default:					 		 
              fprintf(stderr, "Usage: %s [-w] [-b <port>]\n", argv[0]);
              fprintf(stderr, "\t-w         - Wait for umurmurd to create shm area. useful if you need to start from init.d script\n" );
              fprintf(stderr, "\t-b <port>  - Change this to the port used when starting umurmurd. Defaults to \"/umurmurd:64738\" \n");
              exit(EXIT_FAILURE);
        }
    }

      shmptr = NULL;
      
      if( !bindport )
      {
        bindport = 64738;
      }
      
      sprintf( shm_file_name, "/umurmurd:%i", bindport );
            
      if( wait )
          shm_statem = WAIT_ATTACH_SHM;
          
        while( shm_statem )
        {
          switch( shm_statem )
          {
              case RUN_SHM:
                    run_shm();
                    break;          
              case WAIT_ATTACH_SHM:
                    printf( "Waiting for umurmurd to be run\n\r"); fflush(stdout);
                    while( ( shm_fd = shm_open( shm_file_name, O_RDONLY, 0666 ) ) == -1 )
                       sleep( 1 );
                    shm_statem = MAT_SHM;
                    break;
              case TRY_ATTACH_SHM:
                    if( ( shm_fd = shm_open( shm_file_name, O_RDONLY, 0666 ) ) == -1 )
                    {
                        printf( "umurmurd doesn't seem to be running\n\r" );                        
                        exit(EXIT_FAILURE);
                    }
                    shm_statem = MAT_SHM;
                    break;
             case MAT_SHM:                  
                    fstat( shm_fd, &buf);                                       
                    if( ( shmptr = mmap(0, buf.st_size, PROT_READ, MAP_SHARED, shm_fd, 0) ) == MAP_FAILED ) 
                    {
                        exit(EXIT_FAILURE);
                    }                    
                    printf( "umumurd PID: %u\n\r", shmptr->umurmurd_pid );
                    shm_statem = RUN_SHM;                    
                    break;
             case CLEAN_UP_SHM:                   
                              
                    break;
                    
         }
       }
        fflush(stdout);
        return 0;
}

uint8_t check_serverTick(void)
{
  last = shmptr->alive;
  sleep( 1 );  // Sleep for 1 sec
  return(shmptr->alive - last); 
}

void run_shm(void)
{

int cc;

    printf( "\033[2J\033[H" ); fflush(stdout); //clear screen VT100
    printf( "%s  Clients(CONECTED/MAX)  %i/%i\n\n", shm_file_name, shmptr->clientcount, shmptr->server_max_clients );      
          
        for( cc = 0 ; cc < shmptr->server_max_clients ; cc++ )
        {
          
          if( !shmptr->client[cc].authenticated )
            continue; 
            
          printf( "%s@%s:%i in channel: %s\n\
                    \tclient_OS: %s %s\n\
                    \tclient_info: %s\n\
                    \tavailableBandwidth: %i\n\
                    \tOnline(secs): %lu Idle(secs): %lu\n\
                    \tusingUDP=%i\n\
                    \tdeaf=%i, mute=%i\n\
                    \tself_deaf=%i, self_mute=%i\n\
                    \trecording=%i\n\
                    \tbOpus=%i\n\
                    \tisAdmin=%i\n\
                    \tisSuppressed=%i\n\
                    \tUDP_Avg/Var: %3.2f/%3.2f\n\
                    \tTCP_Avg/Var: %3.2f/%3.2f\n\
                    \tUDP_C/TCP_C: %lu/%lu\n", 
                                              shmptr->client[cc].username,
                                              shmptr->client[cc].ipaddress,
                                              shmptr->client[cc].udp_port,
                                              shmptr->client[cc].channel,
                                              shmptr->client[cc].os,
                                              shmptr->client[cc].os_version,
                                              shmptr->client[cc].release,
                                              shmptr->client[cc].availableBandwidth,
                                              shmptr->client[cc].online_secs,
                                              shmptr->client[cc].idle_secs,
                                                             
                                              shmptr->client[cc].bUDP,
                                              shmptr->client[cc].deaf,
                                              shmptr->client[cc].mute,
                                              shmptr->client[cc].self_deaf,
                                              shmptr->client[cc].self_mute,
                                              shmptr->client[cc].recording,
                                              shmptr->client[cc].bOpus,
                                              
                                              shmptr->client[cc].isAdmin,
                                              shmptr->client[cc].isSuppressed,
                                                                              
                                              shmptr->client[cc].UDPPingAvg,
                                              shmptr->client[cc].UDPPingVar,
                                              shmptr->client[cc].TCPPingAvg,
                                              shmptr->client[cc].TCPPingVar,
                                              shmptr->client[cc].UDPPackets,
                                              shmptr->client[cc].TCPPackets ); fflush(stdout);  // fflush need because of sleep() call
        }
        if( !check_serverTick() )
        {
            exit(EXIT_FAILURE); //You dont have to exit you could just report the fact that the data is not valid 
        }
}