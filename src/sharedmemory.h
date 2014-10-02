#ifndef SHAREDMEMORY_H_777736932196
#define SHAREDMEMORY_H_777736932196

#include <stdlib.h>
#include <string.h>

#include <sys/shm.h>

#include "util.h"
#include "conf.h" 
#include "client.h"
#include "channel.h"
#include "sharedmemory_struct.h"

int shmid;
shm_t *shmptr; 

void Sharedmemory_init(void);
void Sharedmemory_update(void);
void Sharedmemory_deinit(void);

#endif  // SHAREDMEMORY_H_777736932196