#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <proc/procps.h>
#include "../../src/sharedmemory.h"


struct shmid_ds buf;
enum{ NOP_SHM, WAIT_ATTACH_SHM, TRY_ATTACH_SHM, MAT_SHM, CLEAN_UP_SHM, RUN_SHM };



void run_shm(void);


int main(int argc, char **argv) 
{
  int wait = 0, opt;
  unsigned int shm_statem = TRY_ATTACH_SHM;
  
  key_t key = 0x53021d79;
  //key = ftok(".", 'S');  // using my own key for now. makes dev easier will fix

    while ((opt = getopt(argc, argv, "w")) != -1) 
    {
        switch (opt) 
        {
           case 'w':
              wait = 1;
              break;
           default: /* '?' */
              fprintf(stderr, "Usage: %s [-w]\n", argv[0]);
              fprintf(stderr, "\t-w         - Wait for umurmurd to create shm area. useful if you need to start from init.d script\n" );
                                            //My version of this talks to custom PIC18 hardware acting as a i2c slave to a RaspberryPI to 
                                            //sound buzzer and turn on a LED when my umurmurd server has users in it. I leave this in here
                                            //in case you need it.  
              exit(EXIT_FAILURE);
        }
    }

   
      
          
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
                    printf( "waiting on umurmurd to be run\n\r"); fflush(stdout);
                    while( ( shmid = shmget( key, 0, 0) ) == -1 )
                       sleep( 1 );
                    shm_statem = MAT_SHM;
                    break;
              case TRY_ATTACH_SHM:
                    if( ( shmid = shmget( key, 0, 0) ) == -1 )
                    {
                        perror("shmget");
                        printf( "umurmurd doesn't seem to be running\n\r" );                        
                        exit(EXIT_FAILURE);
                    }
                    shm_statem = MAT_SHM;
                    break;
             case MAT_SHM:                                       
                    if( ( shmptr = shmat( shmid, 0, 0 ) ) == (void *) (-1) )
                    {
                        perror("shmat");
                        exit(EXIT_FAILURE);
                    }
                    printf( "shmid: %i\n\r", shmid );
                    printf( "Connected to umumurd PID: %u\n\r", shmptr->umurmurd_pid );
                    sleep( 1 );
                    shm_statem = RUN_SHM;                    
                    break;
             case CLEAN_UP_SHM:                   
                    shmdt( shmptr );          
                    break;                    
         }
       }
       fflush(stdout);
       return 0;
}


void run_shm(void)
{
  int cc;
    
    shmctl( shmid, IPC_STAT, &buf );   //MJP BUG check for errors here

      printf("\033[2J\033[H"); //clear screen VT100
          
      printf( "attach: %lu SCC: %i SMC: %i\n", (unsigned long int)buf.shm_nattch, shmptr->clientcount, shmptr->server_max_clients );
      
      for( cc = 0 ; cc < shmptr->server_max_clients ; cc++ )
      {    
        if( !shmptr->client[cc].authenticated )
            continue; 
            
        printf( "%s@%s:%i in channel: %s\n\
                \tOnline(secs): %lu Idle(secs): %lu\n\
                \tusingUDP=%i\n\
                \tdeaf=%i, mute=%i\n\
                \tself_deaf=%i, self_mute=%i\n\
                \trecording=%i\n\
                \tbOpus=%i\n\
                \tUDP_Avg/Var: %3.2f/%3.2f \n\
                \tTCP_Avg/Var: %3.2f/%3.2f \n\
                \tUDP_C/TCP_C: %lu/%lu\n", 
                                          shmptr->client[cc].username,
                                          shmptr->client[cc].ipaddress,
                                          shmptr->client[cc].udp_port,
                                          shmptr->client[cc].channel,
                                          shmptr->client[cc].online_secs,
                                          shmptr->client[cc].idle_secs,
                                                             
                                          shmptr->client[cc].bUDP,
                                          shmptr->client[cc].deaf,
                                          shmptr->client[cc].mute,
                                          shmptr->client[cc].self_deaf,
                                          shmptr->client[cc].self_mute,
                                          shmptr->client[cc].recording,
                                          shmptr->client[cc].bOpus,
                                                                              
                                          shmptr->client[cc].UDPPingAvg,
                                          shmptr->client[cc].UDPPingVar,
                                          shmptr->client[cc].TCPPingAvg,
                                          shmptr->client[cc].TCPPingVar,
                                          shmptr->client[cc].UDPPackets,
                                          shmptr->client[cc].TCPPackets
                                                                         ); fflush(stdout);  // fflush need because of sleep() call
      }          
      sleep( 1 );  // Sleep for 1 sec
}