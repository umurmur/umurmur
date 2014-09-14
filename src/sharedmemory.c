#include "sharedmemory.h"

void Sharedmemory_init(void) 
{

  key_t key = 0x53021d79;
  int server_max_clients = getIntConf(MAX_CLIENTS);  
  int shmptr_size =  sizeof( shm_t  ) + (sizeof( shmclient_t ) * server_max_clients);
  
  //key =  ftok( ".", 'S' );  //MJP BUG this needs fixing.. also how to handle multi copys of umurmur bound to diff ports or IPs  option to pass key on cmdline?  
  shmid = shmget( key, shmptr_size, IPC_CREAT | 0666 );    

  Log_info("SHM_KEY: 0x%x", key );

        if( ( shmptr = ( shm_t *) shmat( shmid, 0, 0 ) ) == (shm_t *) (-1) )
        {
                perror("shmat");
                exit(1); //MJP BUG should report error and just not use shm dont exit
        }
        memset( shmptr, 0, shmptr_size );                                     
  shmptr->umurmurd_pid = getpid();
  shmptr->server_max_clients = server_max_clients;  
}

void Sharedmemory_update(void) 
{

  static size_t bt_end = sizeof(  bool_t  ) * 8,   //compute once
                et_end = sizeof( etimer_t ) * 3,
                pa_end = sizeof(  float   ) * 4,
                pc_end = sizeof( uint32_t ) * 2;
                
 unsigned int cc = 0;
 client_t *client_itr = NULL;
 
 memset( &shmptr->client[0], 0, sizeof( shmclient_t ) * shmptr->server_max_clients );
 shmptr->clientcount = Client_count();
 
 
 
 while( Client_iterate(&client_itr) != NULL ) {
 

                                                                                              
      if( client_itr->authenticated )
      {
        
        channel_t *channel = client_itr->channel;
                                                                                                                                  
        strncpy( shmptr->client[cc].username, client_itr->username, 120 );
        strncpy( shmptr->client[cc].ipaddress, Util_clientAddressToString( client_itr ) , 45 );
        shmptr->client[cc].tcp_port = Util_clientAddressToPortTCP( client_itr );
        shmptr->client[cc].udp_port = Util_clientAddressToPortUDP( client_itr );
        strncpy( shmptr->client[cc].channel, channel->name, 120 );
        memcpy( &shmptr->client[cc].bUDP, &client_itr->bUDP, bt_end );
        memcpy( &shmptr->client[cc].lastActivity, &client_itr->lastActivity, et_end );
        memcpy( &shmptr->client[cc].UDPPingAvg, &client_itr->UDPPingAvg, pa_end );
        memcpy( &shmptr->client[cc].UDPPackets, &client_itr->UDPPackets, pc_end );
      }  
      cc++;
      
 }
 
}

void Sharedmemory_deinit(void) 
{
  shmctl( shmid, IPC_RMID, 0 );   //Mark shmid for removal.
  shmdt( shmptr );
}