typedef struct
{
  char username[121];
  char ipaddress[46];
  int tcp_port, udp_port;
  char channel[121];
  bool_t bUDP, authenticated, deaf, mute, self_deaf, self_mute, recording, bOpus;
  etimer_t lastActivity, connectTime, idleTime;
  float UDPPingAvg, UDPPingVar, TCPPingAvg, TCPPingVar;
  uint32_t UDPPackets, TCPPackets;

}shmclient_t;

typedef struct
{

  int clientcount, server_max_clients;
  unsigned int umurmurd_pid; //Use this to make sure umurmurd is still running so I can allow more than one connection.
  shmclient_t client[];    //MJP BUG: Use max usersetting from conf file
  
}shm_t;