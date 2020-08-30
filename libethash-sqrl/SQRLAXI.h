#ifndef _SQRLAXI_HEADER
#define _SQRLAXI_HEADER

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#else
#ifndef bool
typedef uint8_t bool;
#define true 1
#define false 0
#endif

#endif

typedef struct _SQRLAXI * SQRLAXIRef;

typedef enum {
  SQRLAXIConnectionTCP,
  SQRLAXIConnectionFTDI
} SQRLAXIConnectionType;

typedef enum {
  SQRLAXIResultOK = 0,
  SQRLAXIResultFailed,
  SQRLAXIResultInvalidParam,
  SQRLAXIResultTimedOut,
  SQRLAXIResultCRCFailed,
  SQRLAXIResultBusy,
  SQRLAXIResultNotConnected
} SQRLAXIResult;

#ifndef CALLBACK_API_C
#define CALLBACK_API_C(_type, _name) _type (* _name)
#endif

typedef CALLBACK_API_C(void, SQRLAXIInterruptCallback)(SQRLAXIRef axi, uint8_t interrupt, uint64_t interruptData, void * context);

// Lifecycle - TCP connections are persistent / auto-reconnect

// Create will stall until TCP connection or FTDI connection is established
SQRLAXIRef SQRLAXICreate(SQRLAXIConnectionType connection, char * hostOrFTDISerial, uint16_t port);
void SQRLAXIDestroy(SQRLAXIRef * self);

// Access connected status of SQRLAXI Object
SQRLAXIResult SQRLAXIIsConnected(SQRLAXIRef self);

// Write to an AXI address
SQRLAXIResult SQRLAXIWrite(SQRLAXIRef self, uint32_t data, uint64_t address, bool waitDone);
// Write a bulk of data
SQRLAXIResult SQRLAXIWriteBulk(SQRLAXIRef self, uint8_t * buf, uint32_t len, uint64_t address, uint8_t swapEndian);
// Read from an AXI address
SQRLAXIResult SQRLAXIRead(SQRLAXIRef self, uint32_t * dataOut, uint64_t address);

// Issues a uart "SelfTest" command, which does not depend on the AXI bus working
SQRLAXIResult SQRLAXITest(SQRLAXIRef self);

// DMA support
SQRLAXIResult SQRLAXICDMAWriteBytes(SQRLAXIRef self, uint8_t *buffer, uint32_t len, uint64_t destAddr);
SQRLAXIResult SQRLAXICDMAReadBytes(SQRLAXIRef self, uint8_t *buffer, uint32_t len, uint64_t srcAddr);
SQRLAXIResult SQRLAXICDMACopyBytes(SQRLAXIRef self, uint64_t srcAddr, uint64_t destAddr, uint64_t len);

// Register a callback for interrupts (Disables internal interrupt queue)
SQRLAXIResult SQRLAXIRegisterForInterrupts(SQRLAXIRef self, uint8_t interrupt, SQRLAXIInterruptCallback callback, void * context); 

// Block for interrupt (with optional timeout)
SQRLAXIResult SQRLAXIWaitForInterrupt(SQRLAXIRef self, uint8_t interrupt, uint64_t * interruptData, uint32_t timeoutInMs);

// Causes any threads blocked on WaitForInterrupt to immediately kick with SQRLAXIResultTimedOut
SQRLAXIResult SQRLAXIKickInterrupts(SQRLAXIRef self);

// Parameters
SQRLAXIResult SQRLAXISetTimeout(SQRLAXIRef self, uint32_t timeoutInMs);


#ifdef __cplusplus
}
#endif

#endif
