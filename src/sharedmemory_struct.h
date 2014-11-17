typedef struct
{

  char username[121];
  char ipaddress[46];
  int tcp_port, udp_port;
  char channel[121];
  bool_t bUDP, authenticated, deaf, mute, self_deaf, self_mute, recording, bOpus;
  uint32_t online_secs, idle_secs;
  float UDPPingAvg, UDPPingVar, TCPPingAvg, TCPPingVar;
  uint32_t UDPPackets, TCPPackets;

}shmclient_t;

typedef struct
{

  int clientcount, server_max_clients;
  unsigned int umurmurd_pid;
	uint8_t alive; 
  shmclient_t client[];    
  
}shm_t;
