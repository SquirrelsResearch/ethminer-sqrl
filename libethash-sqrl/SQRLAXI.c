#include "SQRLAXI.h"



#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef _WIN32 
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* we need sched_setaffinity() */
#endif
#include <error.h>
#include <sched.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#endif

/* Sanity check for defined OS */
#if defined(__APPLE__) || defined(__MACOSX)
/* MACOSX */
#include <mach/mach.h>
#elif defined(__linux__)
/* linux */
#elif defined(_WIN32)
/* windows */
#include <windows.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#else
#error "Invalid OS configuration"
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET 0
#endif

#ifdef _WIN32
#define sqrlthread_t HANDLE
#define sqrlmutex_t CRITICAL_SECTION
#define sqrlcond_t CONDITION_VARIABLE
#define SQRLMutexLock(A) EnterCriticalSection(A)
#define SQRLMutexUnlock(A) LeaveCriticalSection(A)

#define sqrlsocklen_t int
#else
#define sqrlthread_t pthread_t
#define sqrlmutex_t pthread_mutex_t
#define sqrlcond_t pthread_cond_t
#define SQRLMutexLock(A) pthread_mutex_lock(A)
#define SQRLMutexUnlock(A) pthread_mutex_unlock(A)

#define sqrlsocklen_t socklen_t
#endif

typedef struct {
  uint8_t rawReq[16];
  uint8_t rawResp[16];
  bool reqSent;
  bool respRcvd;
  bool respValid;
  bool respTimedOut;
} SQRLAXIPkt;

typedef struct _SQRLAXI {
  SQRLAXIConnectionType type;
#ifdef _WIN32
  SOCKET fd; // Network file descriptor
#else
  int fd; // Network file descriptor
#endif
  char * host;
  uint16_t port;

  // Interrupt callbacks
  SQRLAXIInterruptCallback callbacks[4];
  void * contexts[4];

  // Packet Arguments
  uint8_t seq;
  uint8_t iseq;

  uint8_t wPktWr;
  uint8_t wPktRd;
  SQRLAXIPkt workPkts[256];
  uint8_t iPktWr;
  uint8_t iPktRd;
  SQRLAXIPkt iPkts[256];

  sqrlthread_t wThread; 

  sqrlmutex_t wMutex;
  sqrlcond_t wCond;
  sqrlmutex_t iMutex;
  sqrlcond_t iCond;
} SQRLAXI;	

// Static Helpers
uint16_t ModRTU_CRC(uint8_t * buf, int len);
uint32_t crc32(uint8_t *buf, int len);
uint32_t crc32_endian(uint8_t *buf, int len);
uint8_t _SQRLAXIMakePacket(uint8_t * pkt, uint8_t cmd, uint8_t pseq, uint64_t address, uint32_t data);

// NULL respPkt means we don't care about the response
SQRLAXIResult _SQRLAXIDoTransaction(SQRLAXIRef self, uint8_t * reqPkt, uint8_t * respPkt);

void * _SQRLAXIWorkThread(void * ctx) {
  SQRLAXIRef self = (SQRLAXIRef)ctx;

  // If we are started, the socket is connected
  fd_set rfd;
  int nfds, n, cc;
  uint8_t waitPkt[16];
  uint8_t waitSize = 0;
  uint8_t buf[8192];
  uint8_t yes = 1;
  while (self->fd != INVALID_SOCKET) {
    FD_ZERO(&rfd);
    nfds = 0;
    FD_SET(self->fd, &rfd);
    nfds = (int)(self->fd)+1;
    
    #ifdef _WIN32
        struct timeval timeout;
        //gettimeofday(&timeout, NULL);
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        n = select(nfds, &rfd, 0, 0, &timeout);
    #else
        struct timespec timeout;
        timeout.tv_sec = 0;
        timeout.tv_nsec = 10000000; // 86805ns for 115200 baud actual byte rate
        n = pselect(nfds, &rfd, 0, 0, &timeout, 0);
    #endif
	if (n > 0 || errno == EINTR)
	{
          if(FD_ISSET(self->fd, &rfd)) {
            // Data to recv - buffer and packet align  
	    if ((cc = recv(self->fd, buf, sizeof(buf),0)) > 0) {
	      uint8_t * wbuf = buf;
              while ((cc + waitSize) >= 16) {
                memcpy(waitPkt+waitSize, wbuf, (16-waitSize)); 
		wbuf += (16-waitSize);
		cc -= (16-waitSize);
		waitSize = 0;
		// Process waitPkt
                //printf("Got Response pkt: %02hhx, %02hhx\n", waitPkt[0], waitPkt[1]);
		//for(int i=0; i < 16; i++) {
                //  printf("%02hhx", waitPkt[i]);
		//}
		//printf("\n");
		// Check CRC
		uint16_t crc = ModRTU_CRC(waitPkt, 14);
		uint16_t pcrc = (((uint16_t)waitPkt[14] << 8) | waitPkt[15]);
		if (crc != pcrc) {
                  printf("Bad CRC\n");
		}
		// Interrupt?
		if ((waitPkt[0] & 0xF) == 0x7) {
                  // TODO - handle Interrupts
		  //printf("Got Interrupt!\n");
		  if (self->iseq != waitPkt[1]) {
                    printf("Interupts missed - %i -> %i\n", self->iseq, waitPkt[1]);
		  } 
		  self->iseq = waitPkt[1]+1;
		  SQRLMutexLock(&self->iMutex);
                  if ((self->iPktWr + 1) == self->iPktRd) {
                    printf("Interrupt Storm - suppressing queued interrupts until the weather clears\n");
		    // TODO - for now, just clear the interrupt queue entirely if it is being ignored 
		    self->iPktWr = 0;
		    self->iPktRd = 0;
		  } else {
	            uint8_t interrupts = (waitPkt[0] >> 4);
		    bool unhandled = false;
		    for(int i=0; i < 4; i++) {
                      if(interrupts & (1 << i)) {
                        if(self->callbacks[i] == NULL) {
		          unhandled = true;
			} else {
                          // Handle this interrupt callback
			  uint64_t interruptData = (((uint64_t)waitPkt[2]) << 56ULL) |
				                   (((uint64_t)waitPkt[3]) << 48ULL) |
				                   (((uint64_t)waitPkt[4]) << 40ULL) |
				                   (((uint64_t)waitPkt[5]) << 32ULL) |
				                   (((uint64_t)waitPkt[6]) << 24ULL) |
				                   (((uint64_t)waitPkt[7]) << 16ULL) |
				                   (((uint64_t)waitPkt[8]) << 8ULL) |
				                   (((uint64_t)waitPkt[9]) << 0ULL);
			  self->callbacks[i](self, i, interruptData, self->contexts[i]); 
			}
		      }
		    }
                    // Copy the interrupt into the queue if unhandled
		    if (unhandled) {
                      memcpy(self->iPkts[self->iPktWr].rawResp, waitPkt, 16);
                      self->iPkts[self->iPktWr].respRcvd = 1;
		      self->iPkts[self->iPktWr].respValid = (crc == pcrc);
		      self->iPkts[self->iPktWr].respTimedOut = 0;
		      self->iPktWr++;
		    // Alert callers
#ifdef _WIN32
                      WakeAllConditionVariable(&self->iCond);
#else
                      pthread_cond_broadcast(&self->iCond);
#endif
		    }
		  }
		  SQRLMutexUnlock(&self->iMutex);
		} else {
		  // Lookup the packet in our queue...
		  bool found = false;
		  SQRLMutexLock(&self->wMutex);
		  for(uint8_t ptr = self->wPktRd; ptr != self->wPktWr; ptr++) {
                    if (((waitPkt[0] & 0xF) == self->workPkts[ptr].rawReq[0]) && (waitPkt[1] == self->workPkts[ptr].rawReq[1])) {
		      if ((waitPkt[0] >> 4) & 0x1) printf("AXI Req Buffer Overflow\n");
		      if (self->workPkts[ptr].respRcvd) {
                        // Caller didn't care for a response, we cleanup here.
	                if (ptr == self->wPktRd) {
	                  // Advance through any recieved packets
                          while((self->wPktRd != self->wPktWr) && (self->workPkts[self->wPktRd].respRcvd)) self->wPktRd++;
	                }
		      } else {
			memcpy(self->workPkts[ptr].rawResp, waitPkt, 16);
			self->workPkts[ptr].respRcvd = 1;
			self->workPkts[ptr].respValid = (crc == pcrc);
			self->workPkts[ptr].respTimedOut = 0;
	                found=true;
		      }
                      break;
		    } 
		  }

		  SQRLMutexUnlock(&self->wMutex);
		  if (found) {
		    // Alert callers
#ifdef _WIN32
                    WakeAllConditionVariable(&self->wCond);
#else
                    pthread_cond_broadcast(&self->wCond);
#endif
		  }
		}

	      }
	      // Save any remaining
	      if (cc) {
                memcpy(waitPkt+waitSize, wbuf, cc); 
		waitSize += cc;
	      }
#ifdef _WIN32
  //uint8_t TCP_QUICKACK = 12;
#else
              if (setsockopt(self->fd, IPPROTO_TCP, TCP_QUICKACK, (char*)(&yes), sizeof(int)) != 0) {
                printf("Failed to set quickack!\n");
              }
#endif  
	    } else {
              // Got disconnected! 
	      printf("Got disconnected\n!");
#ifdef _WIN32
              closesocket(self->fd);
#else
              close(self->fd);
#endif
	      self->fd = INVALID_SOCKET;
	    }
	  }
	} else if (n == 0) {
          // TODO - any busy work
	} else {
          printf("Select Error: %i\n", n);
	  return NULL;
	}
  }
  return NULL;
}

SQRLAXIResult _SQRLAXIDoTransaction(SQRLAXIRef self, uint8_t * reqPkt, uint8_t * respPkt) {
  if (self->fd == INVALID_SOCKET) return SQRLAXIResultNotConnected;
  // Lock the work mutex to ensure we're the only ones on the bus
  uint8_t pktSlot=0;
  SQRLMutexLock(&self->wMutex); 
  if (self->wPktWr+1 == self->wPktRd) {
    SQRLMutexUnlock(&self->wMutex);
    return SQRLAXIResultBusy;
  }
  // Place our work packet in the queue
  memcpy(&(self->workPkts[self->wPktWr].rawReq), reqPkt, 16); 
  memset(&(self->workPkts[self->wPktWr].rawResp), 0x0, 16);
  self->workPkts[self->wPktWr].reqSent=1;
  self->workPkts[self->wPktWr].respRcvd = (respPkt == NULL)?true:false; // Causes work loop to clear the packet on response
  self->workPkts[self->wPktWr].respValid = 0;
  self->workPkts[self->wPktWr].respTimedOut = 0;
  pktSlot = self->wPktWr;
  self->wPktWr++; // Auto-wrap to 

  // Send the full packet
  //printf("Sending Packet %02hhx %02hhx\n", reqPkt[0], reqPkt[1]);
  int bytesSent = 0;
  while (bytesSent < 16) {
    int sent = send(self->fd, reqPkt+bytesSent, (16-bytesSent), 0);
    if (sent <= 0) {
      printf("Send failed!\n");
      // Disconnect
#ifdef _WIN32
      closesocket(self->fd);
#else
      close(self->fd); 
#endif
      self->fd = 0;
      SQRLMutexUnlock(&self->wMutex);
      return SQRLAXIResultNotConnected;
    }
    bytesSent += sent;
  }
  SQRLMutexUnlock(&self->wMutex);

  if (respPkt != NULL) {
    // Wait for a response!
    uint32_t timeoutInMs = 10;
    uint8_t timeoutCount = 10;
    for(;;) {
      SQRLMutexLock(&self->wMutex);
#ifdef _WIN32
      SleepConditionVariableCS(&self->wCond, &self->wMutex, timeoutInMs);
#else
      struct timespec timeout;
      timespec_get(&timeout, TIME_UTC);
      time_t sec = (timeout.tv_sec + (timeoutInMs/1000));
      long nsec = (timeout.tv_nsec + ((long)timeoutInMs*1000000ULL));
    
      timeout.tv_sec = (sec + (nsec/1000000000ULL));
      timeout.tv_nsec = (nsec % 1000000000ULL); 
      pthread_cond_timedwait(&self->wCond, &self->wMutex, &timeout);
#endif
      timeoutCount--;

      // Check our pkt
      if (self->workPkts[pktSlot].respRcvd || self->workPkts[pktSlot].respTimedOut) {
	bool timedOut = self->workPkts[pktSlot].respTimedOut; 
	bool valid = self->workPkts[pktSlot].respValid;
        memcpy(respPkt, self->workPkts[pktSlot].rawResp, 16); 
	if (pktSlot == self->wPktRd) {
	  // Advance through any recieved packets
          while((self->wPktRd != self->wPktWr) && (self->workPkts[self->wPktRd].respRcvd)) self->wPktRd++;
	}
        SQRLMutexUnlock(&self->wMutex);
	if (timedOut) return SQRLAXIResultTimedOut;
	if (!valid) return SQRLAXIResultCRCFailed;
	break;
      }
      SQRLMutexUnlock(&self->wMutex);
      if (timeoutCount == 0) {
        printf("AXI Timeout!\n");
	SQRLMutexLock(&self->wMutex);
	self->workPkts[pktSlot].respTimedOut = true;
	self->workPkts[pktSlot].respRcvd = true;
	if (pktSlot == self->wPktRd) {
	  // Advance through any recieved packets
          while((self->wPktRd != self->wPktWr) && (self->workPkts[self->wPktRd].respRcvd)) self->wPktRd++;
	}
	SQRLMutexUnlock(&self->wMutex);
	return SQRLAXIResultTimedOut;
      }
    }
  }

  return SQRLAXIResultOK;
}

// Create will stall until TCP connection or FTDI connection is established
SQRLAXIRef SQRLAXICreate(SQRLAXIConnectionType connection, char * hostOrFTDISerial, uint16_t port) {
  SQRLAXIRef self = (SQRLAXIRef)malloc(sizeof(SQRLAXI));
  if (self) {
    self->fd = INVALID_SOCKET;
    self->port = port;
#ifdef _WIN32
    self->host = (hostOrFTDISerial?_strdup(hostOrFTDISerial):NULL);
#else
    self->host = (hostOrFTDISerial?strdup(hostOrFTDISerial):NULL);
#endif
    self->type = connection;
    self->callbacks[0] = NULL;
    self->callbacks[1] = NULL;
    self->callbacks[2] = NULL;
    self->callbacks[3] = NULL;
    self->seq = 0;
    self->iseq = 0;
    self->wPktWr = 0;
    self->wPktRd = 0;
    self->iPktWr = 0;
    self->iPktRd = 0;

    if (self->type == SQRLAXIConnectionTCP) {
      // Lookup ddress
      int ret=0;
      struct sockaddr_in server_addr;
      server_addr.sin_family = AF_INET;
      server_addr.sin_port = htons(port);
      ret = inet_pton(AF_INET, self->host, &server_addr.sin_addr);
      if (ret != 1) {
        if (ret == -1) {
          perror("inet_pton");
	}
	fprintf(stderr, "failed to convert address %s to binary net address\n", self->host);
	if (self->host) free(self->host);
	free(self);
	return NULL;
      }
      // Open the network connection
      self->fd = socket(AF_INET, SOCK_STREAM, 0);
      if (self->fd == -1) {
        perror("socket");
	if (self->host) free(self->host);
	free(self);
	return NULL;
      }
      int yes=1;
      ret = setsockopt(self->fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&yes, sizeof(int));
      if (ret != 0) {
        perror("NODELAY");// Don't abort on this
      }
      ret = connect(self->fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
      if (ret == -1) {
        perror("connect");
	if (self->host) free(self->host);
	free(self);
	return NULL;
      }  
#ifdef _WIN32
      InitializeCriticalSection(&self->wMutex);
      InitializeConditionVariable(&self->wCond);
      InitializeCriticalSection(&self->iMutex);
      InitializeConditionVariable(&self->iCond);
      self->wThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)_SQRLAXIWorkThread, self,0,NULL);
#else
      pthread_mutex_init(&self->wMutex, NULL);
      pthread_cond_init(&self->wCond, NULL);
      pthread_mutex_init(&self->iMutex, NULL);
      pthread_cond_init(&self->iCond, NULL);

      pthread_create(&self->wThread, NULL, _SQRLAXIWorkThread, self);
#endif

    }  
    return self;
  }
  return NULL;
}

void SQRLAXIDestroy(SQRLAXIRef * self) {
  if (self != NULL && *self != NULL) {
    SQRLAXIRef dead = *self;
    *self = NULL;
    if (dead->fd != INVALID_SOCKET) {
#ifdef _WIN32
      closesocket(dead->fd);
#else
      shutdown(dead->fd, SHUT_RDWR);
      close(dead->fd);
#endif
 #ifdef _WIN32
      WaitForSingleObject(dead->wThread, INFINITE);
#else
      pthread_join(dead->wThread, NULL);
#endif

    }
    if (dead->host) {
      free(dead->host); dead->host = NULL;
    } 
  }
}

// Access connected status of SQRLAXI Object
SQRLAXIResult SQRLAXIIsConnected(SQRLAXIRef self) {
  return (self->fd != INVALID_SOCKET)?SQRLAXIResultOK:SQRLAXIResultNotConnected;
}

// Write to an AXI address - MUST BE THREADSAFE
SQRLAXIResult SQRLAXIWrite(SQRLAXIRef self, uint32_t data, uint64_t address, bool waitDone) {
  if (self->fd == INVALID_SOCKET) return SQRLAXIResultNotConnected;

  // Do the transaction
  uint8_t reqPkt[16];
  uint8_t respPkt[16];
  _SQRLAXIMakePacket(reqPkt, 0x02, self->seq++, address, data);
  SQRLAXIResult res = _SQRLAXIDoTransaction(self, reqPkt, (waitDone?respPkt:NULL));
  if (res == SQRLAXIResultOK) {
    // Valid packet
    // Should be a mirror
  }
  return res;
}

// Read from an AXI address - MUST BE THREADSAFE
SQRLAXIResult SQRLAXIRead(SQRLAXIRef self, uint32_t * dataOut, uint64_t address) {
  if (self->fd == INVALID_SOCKET) return SQRLAXIResultNotConnected;
  // Do the transaction
  uint8_t reqPkt[16];
  uint8_t respPkt[16];
  _SQRLAXIMakePacket(reqPkt, 0x01, self->seq++, address, 0xAAAAAAAA);
  SQRLAXIResult res = _SQRLAXIDoTransaction(self, reqPkt, respPkt);
  if (res == SQRLAXIResultOK) {
    // Valid packet
    uint32_t result = 0;
    result |= (respPkt[10] << 24);
    result |= (respPkt[11] << 16);
    result |= (respPkt[12] << 8);
    result |= (respPkt[13] << 0);
    *dataOut = result;
  }
  return res;
}

// Write to an AXI address - MUST BE THREADSAFE
SQRLAXIResult SQRLAXIWriteBulk(SQRLAXIRef self, uint8_t * buf, uint32_t len, uint64_t address, uint8_t swapEndian) {
  if (self->fd == INVALID_SOCKET) return SQRLAXIResultNotConnected;
  if (len % 16 != 0) return SQRLAXIResultInvalidParam;
  // Do the transaction
  uint8_t reqPkt[16];
  uint8_t respPkt[16];
  _SQRLAXIMakePacket(reqPkt, (1 << 6) | 0x02, self->seq++, address, len);

  uint8_t pktSlot=0;
  SQRLMutexLock(&self->wMutex); 
  if (self->wPktWr+1 == self->wPktRd) {
    SQRLMutexUnlock(&self->wMutex);
    return SQRLAXIResultBusy;
  }
  // Place our work packet in the queue
  memcpy(&(self->workPkts[self->wPktWr].rawReq), reqPkt, 16); 
  self->workPkts[self->wPktWr].rawReq[0] = 0x2; // Response doesn't have bulk flag
  memset(&(self->workPkts[self->wPktWr].rawResp), 0x0, 16);
  self->workPkts[self->wPktWr].reqSent=1;
  self->workPkts[self->wPktWr].respRcvd = (respPkt == NULL)?true:false; // Causes work loop to clear the packet on response
  self->workPkts[self->wPktWr].respValid = 0;
  self->workPkts[self->wPktWr].respTimedOut = 0;
  pktSlot = self->wPktWr;
  self->wPktWr++; // Auto-wrap to 

  //printf("Sending Bulk Header Packet %02hhx %02hhx\n", reqPkt[0], reqPkt[1]);
  int bytesSent = 0;
  while (bytesSent < 16) {
    int sent = send(self->fd, reqPkt+bytesSent, (16-bytesSent), 0);
    if (sent <= 0) {
      printf("Send failed!\n");
      // Disconnect
#ifdef _WIN32
      closesocket(self->fd);
#else
      close(self->fd); 
#endif
      self->fd = 0;
      SQRLMutexUnlock(&self->wMutex);
      return SQRLAXIResultNotConnected;
    }
    bytesSent += sent;
  }

  // Do not unlock yet! send the entire data
  // Send the data - 16 bytes at a time!
  for(uint32_t i=0; i < len; i+= 16) {
    // Data on the AXI bus is in 32 bit words, which
    // write into memory as byte [3][2][1][0] - 
    // we need to do an endian swap here if we want
    // our bulk data to be accurately represented
    // ASKING to swap endian is actually not performing this swap
    uint8_t * sdata = buf + i;
    uint8_t swap[16];
    if (!swapEndian) {
      sdata = &(swap[0]);
      for (int j=0; j < 4; j++) {
        swap[j*4+0]=buf[j*4+i+3];
        swap[j*4+1]=buf[j*4+i+2];
        swap[j*4+2]=buf[j*4+i+1];
        swap[j*4+3]=buf[j*4+i];
      }
    }
    bytesSent = 0;
    while (bytesSent < 16) {
      int sent = send(self->fd, sdata+bytesSent, (16-bytesSent), 0);
      if (sent <= 0) {
        printf("BulkSend failed!\n");
        // Disconnect
#ifdef _WIN32
        closesocket(self->fd);
#else
        close(self->fd); 
#endif
        self->fd = 0;
        SQRLMutexUnlock(&self->wMutex);
        return SQRLAXIResultNotConnected;
      }
      bytesSent += sent;
    }   
  }
  // Now it is safe to unlock 
  SQRLMutexUnlock(&self->wMutex);

  // Wait for a response!
  uint32_t timeoutInMs = 10;
  uint8_t timeoutCount = 10;
  for(;;) {
    SQRLMutexLock(&self->wMutex);
#ifdef _WIN32
    SleepConditionVariableCS(&self->wCond, &self->wMutex, timeoutInMs);
#else
    struct timespec timeout;
    timespec_get(&timeout, TIME_UTC);
    time_t sec = (timeout.tv_sec + (timeoutInMs/1000));
    long nsec = (timeout.tv_nsec + ((long)timeoutInMs*1000000ULL));
   
    timeout.tv_sec = (sec + (nsec/1000000000ULL));
    timeout.tv_nsec = (nsec % 1000000000ULL); 
    pthread_cond_timedwait(&self->wCond, &self->wMutex, &timeout);
#endif
    timeoutCount--;
    //printf("Wokeup for bulk\n");
    // Check our pkt
    if (self->workPkts[pktSlot].respRcvd || self->workPkts[pktSlot].respTimedOut) {
      bool timedOut = self->workPkts[pktSlot].respTimedOut;
      bool valid = self->workPkts[pktSlot].respValid;
      memcpy(respPkt, self->workPkts[pktSlot].rawResp, 16);
      if (pktSlot == self->wPktRd) {
        // Advance through any recieved packets
        while((self->wPktRd != self->wPktWr) && (self->workPkts[self->wPktRd].respRcvd)) self->wPktRd++;
      }
      SQRLMutexUnlock(&self->wMutex);
      if (timedOut) return SQRLAXIResultTimedOut;
      if (!valid) return SQRLAXIResultCRCFailed;
      break;
    }
    SQRLMutexUnlock(&self->wMutex);
    if(timeoutCount == 0) {
      printf("AXI Timeout!\n");
      SQRLMutexLock(&self->wMutex);
      self->workPkts[pktSlot].respTimedOut = true;
      self->workPkts[pktSlot].respRcvd = true;
      if (pktSlot == self->wPktRd) {
        // Advance through any recieved packets
        while((self->wPktRd != self->wPktWr) && (self->workPkts[self->wPktRd].respRcvd)) self->wPktRd++;
      }
      SQRLMutexUnlock(&self->wMutex);
      return SQRLAXIResultTimedOut;
    }
  }
  //printf("BulkDone\n");

  // Verify the response
  if ((respPkt[0] >> 6) != 0x0) return SQRLAXIResultFailed;
  uint32_t ourCRC = (swapEndian?crc32(buf,len):crc32_endian(buf,len));
  uint32_t calcCRC = 0;
  calcCRC |= respPkt[10] << 24;
  calcCRC |= respPkt[11] << 16;
  calcCRC |= respPkt[12] << 8;
  calcCRC |= respPkt[13];
  if (calcCRC != ourCRC) return SQRLAXIResultCRCFailed; 

  // CRC 32 passed, we're good
  //printf("BulkOk\n");

  return SQRLAXIResultOK;
}

// Support CDMA operations
SQRLAXIResult SQRLAXICDMAWriteBytes(SQRLAXIRef self, uint8_t *buffer, uint32_t len, uint64_t destAddr) {
  // AXI-CDMA core should be at 0x120000
  // BRAM Block is at 0x200000 axi-lite side, and 0x200000000 on 64bit AXI (HBM) side

  if ( ((len+3)/4)*4 != len) {
    printf("WARNING! CDMA data not 32 bit aligned! Unsupported\n");
  }

  // Soft reset core
  SQRLAXIWrite(self, (1<<2), 0x120000, true);

  SQRLAXIResult res = SQRLAXIResultOK;
  // The CDMA source reg is always the same - write it once
  if ((res = SQRLAXIWrite(self, 0x00000000, 0x120018,true)) != 0) {
    return res;
  }
  if ((res = SQRLAXIWrite(self, 0x00000002, 0x12001C,true)) != 0) {
    return res;
  }

  // Operate in up to 64KB chunks (BRAM scratchpad size) 
  uint32_t pos = 0;
  while (pos < len) {
    uint32_t bytesToSend = (len-pos)>65536?65536:(len-pos);

    // Copy to BRAM 
    uint32_t burst=3968;
    for(uint32_t i=0; i < bytesToSend; i += burst) {
      uint32_t burstSize = (bytesToSend-i)>burst?burst:(bytesToSend-i);
      if ((res = SQRLAXIWriteBulk(self, buffer+pos+i, burstSize, 0x200000+i,false)) != 0) {
        return res;
      }
    }
    // Run CDMA Command - Setup Addresses
    //printf("Setting up write to %08x\n", (uint32_t)(destAddr+pos) & 0xFFFFFFFF);
    uint32_t low = (uint32_t)(destAddr+pos) & 0xFFFFFFFF;
    uint32_t high = (uint32_t)((destAddr+pos) >> 32ULL) & 0xFFFFFFFF;
    //printf("%08x %08x\n", low, high);
    if ((res = SQRLAXIWrite(self, low, 0x120020, true)) != 0) {
        return res;
    }
    if ((res = SQRLAXIWrite(self, high, 0x120024, true)) != 0) {
        return res;
    }
    // This triggers the transfer
    //printf("BTT %08x\n", bytesToSend);
    if ((res = SQRLAXIWrite(self, bytesToSend, 0x120028, true)) != 0) {
      return res;
    }
    // Wait for completion! (TODO - could double buffer 32KB packets...)
    uint8_t busy = 1;
    while (busy) {
      uint32_t status=0;
      if ((res = SQRLAXIRead(self, &status, 0x120004)) != 0) {
        return res;
      }
      uint8_t err=0;
      if (status & (1 << 6)) {
        printf("CDMA Decode Error!\n");
        err=1;
      }
      if (status & (1 << 5)) {
        printf("CDMA Slave Error!\n");
        err = 1;
      }
      if (status & (1 << 4)) {
        printf("CDMA Internal Error!\n");
        err = 1;
      }
      busy = (~(status >> 1) & 0x1);
      if (err) {
        // Soft reset core and abort
        SQRLAXIWrite(self, (1<<2), 0x120000, 0);
        return SQRLAXIResultFailed;
      }
    }

    pos += bytesToSend;
  }
  return SQRLAXIResultOK; 
}

SQRLAXIResult SQRLAXICDMAReadBytes(SQRLAXIRef self, uint8_t *buffer, uint32_t len, uint64_t srcAddr) {
  // AXI-CDMA core should be at 0x12000
  // BRAM Block is at 0x20000 axi-lite side, and 0x200000000 on 64bit AXI (HBM) side

  if ( ((len+3)/4)*4 != len) {
    printf("WARNING! CDMA data not 32 bit aligned! Unsupported\n");
  }

  // Soft reset core
  SQRLAXIWrite(self, (1<<2), 0x120000, true);

  SQRLAXIResult res = SQRLAXIResultOK;
  // The CDMA dest reg is always the same - write it once
  if ((res = SQRLAXIWrite(self, 0x00000000, 0x120020, true)) != 0) {
    return res;
  }
  if ((res = SQRLAXIWrite(self, 0x00000002, 0x120024, true)) != 0) {
    return res;
  }

  // Operate in up to 64KB chunks (BRAM scratchpad size) 
  uint32_t pos = 0;
  while (pos < len) {
    uint32_t bytesToRead = (len-pos)>65536?65536:(len-pos);

    // Run CDMA Command - Setup Addresses
    if ((res = SQRLAXIWrite(self, (srcAddr+pos) & 0xFFFFFFFF, 0x120018, true)) != 0) {
        return res;
    }
    if ((res = SQRLAXIWrite(self, ((srcAddr+pos) >> 32ULL) & 0xFFFFFFFF, 0x12001C, true)) != 0) {
        return res;
    }
    // Write BTT to run transaction
    if ((res = SQRLAXIWrite(self, bytesToRead, 0x120028, true)) != 0) {
      return res;
    }

    // Wait for completion! (TODO - could double buffer 32KB packets...)
    uint8_t busy = 1;
    while (busy) {
      uint32_t status=0;
      if ((res = SQRLAXIRead(self, &status, 0x120004)) != 0) {
        return res;
      }
      uint8_t err=0;
      if (status & (1 << 6)) {
        printf("CDMA Decode Error!\n");
        err=1;
      }
      if (status & (1 << 5)) {
        printf("CDMA Slave Error!\n");
        err=1;
      }
      if (status & (1 << 4)) {
        printf("CDMA Internal Error!\n");
        err=1;
      }
      if (err) {
        // Soft reset core and abort
        SQRLAXIWrite(self, (1<<2), 0x120000, 0);
        return SQRLAXIResultFailed;
      }
      busy = (~(status >> 1) & 0x1);
    }

    // Copy from BRAM 
    for(uint32_t i=0; i < bytesToRead; i += 4) {
      uint32_t value = 0;
      if ((res = SQRLAXIRead(self, &value, 0x200000+i)) != 0) {
        return res;
      }
      // SQRLAXIRead reads into HOST endianess, 
      // because we're asking for byte order here - we need to reverse it
      buffer[pos+i+0] = (value >> 0) & 0xff;
      buffer[pos+i+1] = (value >> 8) & 0xff;
      buffer[pos+i+2] = (value >> 16) & 0xff;
      buffer[pos+i+3] = (value >> 24) & 0xff;
    }

    pos += bytesToRead;
  }

  return SQRLAXIResultOK; 
}

SQRLAXIResult SQRLAXICDMACopyBytes(SQRLAXIRef self, uint64_t srcAddr, uint64_t destAddr, uint64_t len) {
  // AXI-CDMA core should be at 0x120000
  // BRAM Block is at 0x200000 axi-lite side, and 0x200000000 on 64bit AXI (HBM) side

  if ( ((len+3)/4)*4 != len) {
    printf("WARNING! CDMA data not 32 bit aligned! Unsupported\n");
  }

  // Soft reset core
  SQRLAXIWrite(self, (1<<2), 0x120000, true);

  SQRLAXIResult res = SQRLAXIResultOK;
  // Operate in up to 8MB chunks (CDMA Maximum transfer size)
  uint64_t pos = 0;
  while (pos < len) {
    uint32_t bytesToSend = (uint32_t)((len-pos)>(8*1024*1024)?(8*1024*1024):(len-pos));

    // Run CDMA Command - Setup Addresses
    //printf("Setting up write to %08x\n", (uint32_t)(destAddr+pos) & 0xFFFFFFFF);
    uint32_t low = (uint32_t)(destAddr+pos) & 0xFFFFFFFF;
    uint32_t high = (uint32_t)((destAddr+pos) >> 32ULL) & 0xFFFFFFFF;
    //printf("Copy to %08x %08x\n", high, low);
    if ((res = SQRLAXIWrite(self, low, 0x120020,true)) != 0) {
        return res;
    }
    if ((res = SQRLAXIWrite(self, high, 0x120024,true)) != 0) {
        return res;
    }
    low = (uint32_t)(srcAddr+pos) & 0xFFFFFFFF;
    high = (uint32_t)((srcAddr+pos) >> 32ULL) & 0xFFFFFFFF;
    //printf("Copy from %08x %08x\n", high, low);
    if ((res = SQRLAXIWrite(self, low, 0x120018,true)) != 0) {
        return res;
    }
    if ((res = SQRLAXIWrite(self, high, 0x12001c,true)) != 0) {
        return res;
    }
    // This triggers the transfer
    //printf("BTT %08x\n", bytesToSend);
    if ((res = SQRLAXIWrite(self, bytesToSend, 0x120028,true)) != 0) {
      return res;
    }
    // Wait for completion! (TODO - could double buffer 32KB packets...)
    uint8_t busy = 1;
    while (busy) {
      uint32_t status=0;
      if ((res = SQRLAXIRead(self, &status, 0x120004)) != 0) {
        return res;
      }
      uint8_t err=0;
      if (status & (1 << 6)) {
        printf("CDMA Decode Error!\n");
        err=1;
      }
      if (status & (1 << 5)) {
        printf("CDMA Slave Error!\n");
        err = 1;
      }
      if (status & (1 << 4)) {
        printf("CDMA Internal Error!\n");
        err = 1;
      }
      busy = (~(status >> 1) & 0x1);
      if (err) {
        // Soft reset core and abort
        SQRLAXIWrite(self, (1<<2), 0x120000,true);
        return SQRLAXIResultFailed;
      }
    }

    pos += bytesToSend;
  }
  return SQRLAXIResultOK;
}

// Register a callback for interrupts (Disables internal interrupt queue)
SQRLAXIResult SQRLAXIRegisterForInterrupts(SQRLAXIRef self, uint8_t interrupt, SQRLAXIInterruptCallback callback, void * context)  {
  if (interrupt > 4) return SQRLAXIResultInvalidParam;
  self->callbacks[interrupt] = callback;
  self->contexts[interrupt] = context;
  return SQRLAXIResultOK;
}

// Block for interrupt (with optional timeout)
SQRLAXIResult SQRLAXIWaitForInterrupt(SQRLAXIRef self, uint8_t interrupt, uint64_t * interruptData, uint32_t timeoutInMs) {
  if (interrupt > 4) return SQRLAXIResultInvalidParam;
  if (self->callbacks[interrupt] != NULL) return SQRLAXIResultFailed;
  if (self->fd == INVALID_SOCKET) return SQRLAXIResultNotConnected;
  // Wait for the specified interrupt to trigger
  bool waited = false;
  for(;;) {
    SQRLMutexLock(&self->iMutex);
    // Check queue
    uint8_t ptr;
    for(ptr=self->iPktRd; ptr != self->iPktWr; ptr++) {
      if (self->iPkts[ptr].respRcvd) {
	bool found = false;
        if(self->iPkts[ptr].respValid) {
          (*interruptData) =  (((uint64_t)self->iPkts[ptr].rawResp[2]) << 56ULL) |
			      (((uint64_t)self->iPkts[ptr].rawResp[3]) << 48ULL) |
			      (((uint64_t)self->iPkts[ptr].rawResp[4]) << 40ULL) |
			      (((uint64_t)self->iPkts[ptr].rawResp[5]) << 32ULL) |
			      (((uint64_t)self->iPkts[ptr].rawResp[6]) << 24ULL) |
			      (((uint64_t)self->iPkts[ptr].rawResp[7]) << 16ULL) |
			      (((uint64_t)self->iPkts[ptr].rawResp[8]) << 8ULL) |
			      (((uint64_t)self->iPkts[ptr].rawResp[9]) << 0ULL);
	  found = ((self->iPkts[ptr].rawResp[0] & (1 << (interrupt+4))) != 0);
	}
	if (ptr == self->iPktRd) {
          self->iPktRd++;
	}
	if (found) {
          SQRLMutexUnlock(&self->iMutex);
	  return SQRLAXIResultOK;
	}
      }
    }
    if (waited) {
      SQRLMutexUnlock(&self->iMutex);
      break;
    }
    #ifdef _WIN32
    SleepConditionVariableCS(&self->iCond, &self->iMutex, timeoutInMs);
#else
    struct timespec timeout;
    timespec_get(&timeout, TIME_UTC);
    time_t sec = (timeout.tv_sec + (timeoutInMs/1000));
    long nsec = (timeout.tv_nsec + ((long)timeoutInMs*1000000ULL));
    
    timeout.tv_sec = (sec + (nsec/1000000000ULL));
    timeout.tv_nsec = (nsec % 1000000000ULL); 
    pthread_cond_timedwait(&self->iCond, &self->iMutex, &timeout);
#endif
    // Wait for wakeup
    SQRLMutexUnlock(&self->iMutex);
    // Check Timeout
    waited = true;
  }
  return SQRLAXIResultTimedOut; 
}

uint16_t ModRTU_CRC(uint8_t * buf, int len)
{
  uint16_t crc = 0xFFFF;

  for (int pos = 0; pos < len; pos++) {
    crc ^= (uint16_t)buf[pos];          // XOR byte into least sig. byte of crc

    for (int i = 8; i != 0; i--) {    // Loop over each bit
      if ((crc & 0x0001) != 0) {      // If the LSB is set
        crc >>= 1;                    // Shift right and XOR 0xA001
        crc ^= 0xA001;
      }
      else                            // Else LSB is not set
        crc >>= 1;                    // Just shift right
    }
  }
  // Note, this number has low and high bytes swapped, so use it accordingly (or swap bytes)
  return crc;
}

uint32_t crc32(uint8_t *buf, int len) {
  uint32_t crc = 0xFFFFFFFF;
  for(int i=0; i < len; i++) {
    uint8_t byte = buf[i];
    for(int j=0; j < 8; j++) {
      if ((crc & 0x1) != (byte & 0x1)) {
        crc = (crc >> 1) ^ 0xEDB88320;
      } else {
        crc = (crc >> 1);
      }
      byte = byte >> 1;
    }
  }
  return crc ^ 0xFFFFFFFF;
}

uint32_t crc32_endian(uint8_t *buf, int len) {
  uint32_t crc = 0xFFFFFFFF;
  for(int i=0; i < len; i++) {
    int oi = ((i/4)*4) + (3 - i%4);
    //printf("%08x -> %08x\n", i, oi);
    uint8_t byte = buf[oi];
    for(int j=0; j < 8; j++) {
      if ((crc & 0x1) != (byte & 0x1)) {
        crc = (crc >> 1) ^ 0xEDB88320;
      } else {
        crc = (crc >> 1);
      }
      byte = byte >> 1;
    }
  }
  return crc ^ 0xFFFFFFFF;
}

uint8_t _SQRLAXIMakePacket(uint8_t * pkt, uint8_t cmd, uint8_t pseq, uint64_t address, uint32_t data) {
  pkt[0] = cmd;
  pkt[1] = pseq;
  pkt[2] = (address >> 56) & 0xff;
  pkt[3] = (address >> 48) & 0xff;
  pkt[4] = (address >> 40) & 0xff;
  pkt[5] = (address >> 32) & 0xff;
  pkt[6] = (address >> 24) & 0xff;
  pkt[7] = (address >> 16) & 0xff;
  pkt[8] = (address >> 8) & 0xff;
  pkt[9] = (address >> 0) & 0xff;
  pkt[10] = (data >> 24) & 0xff;
  pkt[11] = (data >> 16) & 0xff;
  pkt[12] = (data >> 8) & 0xff;
  pkt[13] = (data >> 0) & 0xff;
  uint16_t crc = ModRTU_CRC(pkt, 14);
  pkt[14] = (crc >> 8) & 0xff;
  pkt[15] = (crc >> 0) & 0xff;
  return 16;
}

