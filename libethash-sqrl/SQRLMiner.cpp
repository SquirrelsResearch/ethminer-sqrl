/*
This file is part of ethminer.

ethminer is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ethminer is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ethminer.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 SQRLMiner mines to SQRL FPGAs
*/


#pragma GCC diagnostic ignored "-Wunused-function"

#if defined(__linux__)
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
#endif

#include <libethcore/Farm.h>
#include <ethash/ethash.hpp>

#include "SQRLMiner.h"


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


using namespace std;
using namespace dev;
using namespace eth;

// TODO - Hacky just dump these in
// Compute the MODBUS RTU CRC
static uint16_t ModRTU_CRC(uint8_t * buf, int len)
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

static uint32_t crc32(uint8_t *buf, int len) {
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

static uint32_t crc32_endian(uint8_t *buf, int len) {
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

static uint8_t seq = 0;

static uint8_t SQRLAXIMakePacket(uint8_t * pkt, uint8_t cmd, uint8_t pseq, uint64_t address, uint32_t data) {
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

static uint8_t SQRLAXIDoTransaction(int fd, uint8_t * reqPkt, uint8_t * respPkt) {
  ssize_t res = write(fd, reqPkt, 16);
  if (res != 16) {
    printf("SQRLAXI Write Failed: %zi\n", res);
    exit(1);
    return -1;
  }
  int tread=0;
  while (tread < 16) {
    res = read(fd, respPkt+tread, 16-tread);
    if (res <= 0) {
    exit(1);
    }
    //  printf("ReadRes: %i\n", res);
    //}
    //if (res+tread != 16) {
      //printf("SQRLAXI Read Failed: %zi\n", res);
    //}
    tread+= res;
  }
  uint16_t crc = ModRTU_CRC(respPkt, 14);
  uint16_t pcrc = (((uint16_t)respPkt[14] << 8) | respPkt[15]);
  if (crc != pcrc) {
    printf("SQRLAXI CRC Error %04hx vs %04hx\n", crc, pcrc);
    return -3;
  }
  if (respPkt[1] != reqPkt[1]) {
    printf("Transaction Response Seq off - wanted %i got %i\n", reqPkt[1], respPkt[1]);
    //Usually this will be an 0x3 "BAD CMD" if it
    // came from an invalid CRC (1/65535 chance).
    // the chance that packet was also state altering (a write) is 
    // 1 in 16M...
    // attempt to sync buffer
    res = read(fd, respPkt, 16);
    if (res <= 0) exit(1);
    if (res != 16) {
      printf("Sync Read failed: %li\n", res);
    }
    return -3;
  }
  if (respPkt[0] != reqPkt[0]) {
    printf("Command didnt match response!\n");

    return -3;
  }
  return 0;
}

static uint8_t SQRLAXIRead(int fd, uint32_t * outval, uint32_t address) {
  uint8_t pkt[16];
  uint8_t my_seq = seq++;
  SQRLAXIMakePacket(pkt, 0x01, my_seq, (uint64_t)address, 0xAAAAAAAA);
  uint8_t rpkt[16];
  uint8_t res = SQRLAXIDoTransaction(fd, pkt, rpkt);
  if (res != 0) {
    printf("AXI Transaction Error!: %i\n", res);
    return res;
  }
  uint32_t result = 0;
  result |= (rpkt[10] << 24);
  result |= (rpkt[11] << 16);
  result |= (rpkt[12] << 8);
  result |= (rpkt[13] << 0);
  *outval = result;
  return 0;
}

static uint8_t _SQRLAXIWriteBulk(int fd, uint8_t * buf, uint32_t len, uint32_t address, uint8_t swapEndian) {
  // Like WriteBurst, but uses the more efficient "BulkWrite" command
  // This command ((1 << 6) | 0x02) takes a length in place of the traditional "value" 
  // The implementation is structured such that length MUST be a multiple of 4, and
  // "Should" be a multiple of 16. Otherwise a CRC failure could occur on the next frame
  if (len % 16 != 0) {
    printf("Write Bulk was not 128 bit aligned\n");
  }
  // Lengths up to 4GB supported, but not recommended
  //printf("Bulk write to %016llx of length %08x\n", address, len);
  uint8_t pktBuf[16];
  SQRLAXIMakePacket(pktBuf, (1 << 6) | 0x02, seq++, (uint64_t)address, len);

  int res = write(fd, pktBuf, 16);
  if (res != 16) {
    printf("Bulk Write Header Failed!\n");
  }
  // Send the data - 16 bytes at a time!
  for(uint32_t i=0; i < len; i+= 16) {
    // Data on the AXI bus is in 32 bit words, which
    // write into memory as byte [3][2][1][0] - 
    // we need to do an endian swap here if we want
    // our bulk data to be accurately represented
    // ASKING to swap endian is actually not performing this swap
    if (!swapEndian) {
      uint8_t swap[16];
      for (int j=0; j < 4; j++) {
        swap[j*4+0]=buf[j*4+i+3];
        swap[j*4+1]=buf[j*4+i+2];
        swap[j*4+2]=buf[j*4+i+1];
        swap[j*4+3]=buf[j*4+i];
      }
      res = write(fd, swap, 16);
    } else {
      res = write(fd, buf+i, 16);
    }
    if (res != 16) {
      printf("Bulk Write Data Failed!\n");
    }
  }
  // Read the result
  uint8_t respPkt[16];
  int tread=0;
  while (tread < 16) {
    res = read(fd, respPkt+tread, 16-tread);
    if (res <= 0) exit(1);
    //if (res <= 0) {
    //  printf("ReadRes %i\n", res);
    //}
    tread+= res;
  }
  uint16_t crc = ModRTU_CRC(respPkt, 14);
  uint16_t pcrc = (((uint16_t)respPkt[14] << 8) | respPkt[15]);
  if (crc != pcrc) {
    printf("SQRLAXI CRC Error %04hx vs %04hx\n", crc, pcrc);
    return -3;
  }
  //printf("%02hhx vs %02hhx\n", respPkt[1], seq-1);
  if ((respPkt[0] >> 6) != 0x0) {
    printf("SQRLAXI Bulk Write AXI Error: %i\n", (respPkt[0] >> 6));
  } else {
    uint32_t ourCRC = (swapEndian?crc32(buf,len):crc32_endian(buf, len));
    uint32_t calcCRC = 0;
    calcCRC |= respPkt[10] << 24;
    calcCRC |= respPkt[11] << 16;
    calcCRC |= respPkt[12] << 8;
    calcCRC |= respPkt[13];
    if (calcCRC != ourCRC) {
      printf("Bulk CRC mismatch\n");
      printf("SQRLAXI Bulk Final CRC: %02x%02x%02x%02x vs %08x\n", respPkt[10], respPkt[11], respPkt[12], respPkt[13], ourCRC);
      printf("SQRLAXI Bulk Final Addr: %02x%02x%02x%02x\n", respPkt[6], respPkt[7], respPkt[8], respPkt[9]);
      return -3;
    }
  }
  return 0;
}

static uint8_t SQRLAXIWriteBulk(int fd, uint8_t * buf, uint32_t len, uint32_t address) {
  return _SQRLAXIWriteBulk(fd,buf,len,address,0);
}

static uint8_t SQRLAXIWriteBurst(int fd, uint8_t * buf, uint32_t len, uint32_t address) {
  // Write up to 1KB in a burst of 255 transactions before
  // reading back the result buffer
  if (len % 4 != 0) {
    printf("Write Burst was not 32 bit aligned/length!\n");
    return -1;
  }
  if (len > 512) {
    printf("Write Burst exceeded 512 bytes!\n");
    return -1;
  }

  uint8_t start_seq = seq;
  uint8_t pktBuf[2048];
  for(uint32_t i=0; i < len; i += 4) {
    uint32_t value = 0;
    value |= buf[i+0] << 24;
    value |= buf[i+1] << 16;
    value |= buf[i+2] << 8;
    value |= buf[i+3] << 0;
    SQRLAXIMakePacket(pktBuf+ i*4, 0x02, seq++, (uint64_t)address+i, value);
    uint8_t falseCRC=0;
    uint32_t cnt=0;
    do {
      if (i >= 4) {
        // Check if we would generate a spurious CRC
        falseCRC = 0;
        for(int j=0; j < 15; j++) {
          uint16_t crc = ModRTU_CRC(pktBuf + i*4 - j - 1, 14);
          uint16_t pcrc = (((uint16_t)pktBuf[i*4 - j - 1 + 14] << 8) | pktBuf[i*4 - j - 1 + 15]);
          if (crc == pcrc) {
            printf("Byte pattern will create false good CRC %i - %02hhx!\n", j, seq);
            falseCRC = 1;
            if (j == 14) {
              // CRC failed in command bit, Use our sequence number to modify the previous packet!
              pktBuf[(i-4)*4+1] = seq-1;
              uint16_t ncrc = ModRTU_CRC(pktBuf + (i-4)*4, 14);
              pktBuf[(i-4)*4+14] = ncrc >> 8;
              pktBuf[(i-4)*4+15] = ncrc & 0xff;
            }
            // Modifying sequence number to prevent.
            SQRLAXIMakePacket(pktBuf+ i*4, 0x02, seq++, (uint64_t)address+i, value);
            cnt++;
            if (cnt > 256) {
              printf("All sequence numbers were valid! - Can'tFix\n");
              for(int j=0; j < 32; j++) {
                 printf("%02hhx", pktBuf[i*4-16 + j]);
              }
	      printf("\n");
              falseCRC=0;
            }
          }
        }
      }
    } while (falseCRC);
  }
  // Send all at once
  ssize_t r  = write(fd, pktBuf, len*4);
  if (r != len*4) {
    printf("Write was short: %li vs %i\n", r, len*4);
  }

  // Recv the results and check
  uint8_t respPkt[16];
  int res;
  for(uint32_t i=0; i < len; i += 4) {
    int tread=0;
    while (tread < 16) {
      res = read(fd, respPkt+tread, 16-tread);
      if (res <=0) exit(1);
      //if (res <= 0) {
      //  printf("ReadRes %i\n", res);
      //}
      tread+= res;
    }
    uint16_t crc = ModRTU_CRC(respPkt, 14);
    uint16_t pcrc = (((uint16_t)respPkt[14] << 8) | respPkt[15]);
    if (crc != pcrc) {
      printf("SQRLAXI CRC Error %04hx vs %04hx\n", crc, pcrc);
      return -3;
    }
    if (respPkt[1] != start_seq) {
      if(respPkt[1] == (uint8_t)(start_seq+1)) {
        start_seq++;
      } else if (respPkt[1] == (uint8_t)(start_seq + 2)) {
        start_seq += 2;
      } else {
        printf("Response Seq off - wanted %i got %i, recovering...\n", start_seq, respPkt[1]);
        //Usually this will be an 0x3 "BAD CMD" if it
        // came from an invalid CRC (1/65535 chance).
        // the chance that packet was also state altering (a write) is 
        // 1 in 16M...
        // attempt to sync buffer
        i-=4;
        continue;
      }
    }
    start_seq++;
    if (respPkt[0] != 0x2) {
      printf("Command didnt match response!\n");

      return -3;
    }
  }
  return 0;
}

static uint8_t SQRLAXIWrite(int fd, uint32_t value, uint32_t address) {
  uint8_t pkt[16];
  uint8_t my_seq = seq++;
  SQRLAXIMakePacket(pkt, 0x02, my_seq, (uint64_t)address, value);
  uint8_t rpkt[16];
  uint8_t res = SQRLAXIDoTransaction(fd, pkt, rpkt);
  if (res != 0) {
    printf("AXI Transaction Error!: %i\n", res);
    printf("WriteResp:\n");
    for(int i=0;i<16;i++) {
      printf("%02hhx", rpkt[i]);
    }
    printf("\n");
  }
  return res;
}

/* AXI-CDMA core registers
  0x00 - CDMA Contorl
  0x04 - CDMA Status
  // Descriptors/Scatter Gather unused
  0x08 - Current Descriptor Pointer
  0x0C - Current Descriptor MSB (for 64 bit)
  0x10 - Tail Descriptor Pointer
  0x14 - Tail Descriptor MSB
  // Direct mode used
  0x18 - SourceAddr;
  0x1C - SourceAddr MSB
  0x20 - DestAddr;
  0x24 - DestAddr MSB
  0x28 - BytesToTransfer
*/

static uint8_t SQRLAXICDMAWriteBytes(int fd, uint8_t *buffer, uint32_t len, uint64_t destAddr) {
  // AXI-CDMA core should be at 0x120000
  // BRAM Block is at 0x200000 axi-lite side, and 0x200000000 on 64bit AXI (HBM) side

  if ( ((len+3)/4)*4 != len) {
    printf("WARNING! CDMA data not 32 bit aligned! Unsupported\n");
  }

  // Soft reset core
  SQRLAXIWrite(fd, (1<<2), 0x120000);

  uint8_t res = 0;
  // The CDMA source reg is always the same - write it once
  if ((res = SQRLAXIWrite(fd, 0x00000000, 0x120018)) != 0) {
    return res;
  }
  if ((res = SQRLAXIWrite(fd, 0x00000002, 0x12001C)) != 0) {
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
      if ((res = SQRLAXIWriteBulk(fd, buffer+pos+i, burstSize, 0x200000+i)) != 0) {
        return res;
      }
    }
    // Run CDMA Command - Setup Addresses
    //printf("Setting up write to %08x\n", (uint32_t)(destAddr+pos) & 0xFFFFFFFF);
    uint32_t low = (uint32_t)(destAddr+pos) & 0xFFFFFFFF;
    uint32_t high = (uint32_t)((destAddr+pos) >> 32ULL) & 0xFFFFFFFF;
    //printf("%08x %08x\n", low, high);
    if ((res = SQRLAXIWrite(fd, low, 0x120020)) != 0) {
        return res;
    }
    if ((res = SQRLAXIWrite(fd, high, 0x120024)) != 0) {
        return res;
    }
    // This triggers the transfer
    //printf("BTT %08x\n", bytesToSend);
    if ((res = SQRLAXIWrite(fd, bytesToSend, 0x120028)) != 0) {
      return res;
    }
    // Wait for completion! (TODO - could double buffer 32KB packets...)
    uint8_t busy = 1;
    while (busy) {
      uint32_t status=0;
      if ((res = SQRLAXIRead(fd, &status, 0x120004)) != 0) {
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
        SQRLAXIWrite(fd, (1<<2), 0x120000);
        return 1;
      }
    }

    pos += bytesToSend;
  }
  return 0;
}

static uint8_t SQRLAXICDMAReadBytes(int fd, uint8_t *buffer, uint32_t len, uint64_t srcAddr) {
  // AXI-CDMA core should be at 0x12000
  // BRAM Block is at 0x20000 axi-lite side, and 0x200000000 on 64bit AXI (HBM) side

  if ( ((len+3)/4)*4 != len) {
    printf("WARNING! CDMA data not 32 bit aligned! Unsupported\n");
  }

  // Soft reset core
  SQRLAXIWrite(fd, (1<<2), 0x120000);

  uint8_t res = 0;
  // The CDMA dest reg is always the same - write it once
  if ((res = SQRLAXIWrite(fd, 0x00000000, 0x120020)) != 0) {
    return res;
  }
  if ((res = SQRLAXIWrite(fd, 0x00000002, 0x120024)) != 0) {
    return res;
  }

  // Operate in up to 64KB chunks (BRAM scratchpad size) 
  uint32_t pos = 0;
  while (pos < len) {
    uint32_t bytesToRead = (len-pos)>65536?65536:(len-pos);

    // Run CDMA Command - Setup Addresses
    if ((res = SQRLAXIWrite(fd, (srcAddr+pos) & 0xFFFFFFFF, 0x120018)) != 0) {
        return res;
    }
    if ((res = SQRLAXIWrite(fd, ((srcAddr+pos) >> 32ULL) & 0xFFFFFFFF, 0x12001C)) != 0) {
        return res;
    }
    // Write BTT to run transaction
    if ((res = SQRLAXIWrite(fd, bytesToRead, 0x120028)) != 0) {
      return res;
    }

    // Wait for completion! (TODO - could double buffer 32KB packets...)
    uint8_t busy = 1;
    while (busy) {
      uint32_t status=0;
      if ((res = SQRLAXIRead(fd, &status, 0x120004)) != 0) {
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
        SQRLAXIWrite(fd, (1<<2), 0x120000);
        return 1;
      }
      busy = (~(status >> 1) & 0x1);
    }

    // Copy from BRAM 
    for(uint32_t i=0; i < bytesToRead; i += 4) {
      uint32_t value = 0;
      if ((res = SQRLAXIRead(fd, &value, 0x200000+i)) != 0) {
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

  return 0;
}

static uint8_t SQRLAXICDMACopyBytes(int fd, uint64_t srcAddr, uint64_t destAddr, uint64_t len) {
  // AXI-CDMA core should be at 0x120000
  // BRAM Block is at 0x200000 axi-lite side, and 0x200000000 on 64bit AXI (HBM) side

  if ( ((len+3)/4)*4 != len) {
    printf("WARNING! CDMA data not 32 bit aligned! Unsupported\n");
  }

  // Soft reset core
  SQRLAXIWrite(fd, (1<<2), 0x120000);


  uint8_t res = 0;
  // Operate in up to 8MB chunks (CDMA Maximum transfer size)
  uint64_t pos = 0;
  while (pos < len) {
    uint32_t bytesToSend = (len-pos)>(8*1024*1024)?(8*1024*1024):(len-pos);

    // Run CDMA Command - Setup Addresses
    //printf("Setting up write to %08x\n", (uint32_t)(destAddr+pos) & 0xFFFFFFFF);
    uint32_t low = (uint32_t)(destAddr+pos) & 0xFFFFFFFF;
    uint32_t high = (uint32_t)((destAddr+pos) >> 32ULL) & 0xFFFFFFFF;
    //printf("Copy to %08x %08x\n", high, low);
    if ((res = SQRLAXIWrite(fd, low, 0x120020)) != 0) {
        return res;
    }
    if ((res = SQRLAXIWrite(fd, high, 0x120024)) != 0) {
        return res;
    }
    low = (uint32_t)(srcAddr+pos) & 0xFFFFFFFF;
    high = (uint32_t)((srcAddr+pos) >> 32ULL) & 0xFFFFFFFF;
    //printf("Copy from %08x %08x\n", high, low);
    if ((res = SQRLAXIWrite(fd, low, 0x120018)) != 0) {
        return res;
    }
    if ((res = SQRLAXIWrite(fd, high, 0x12001c)) != 0) {
        return res;
    }
    // This triggers the transfer
    //printf("BTT %08x\n", bytesToSend);
    if ((res = SQRLAXIWrite(fd, bytesToSend, 0x120028)) != 0) {
      return res;
    }
    // Wait for completion! (TODO - could double buffer 32KB packets...)
    uint8_t busy = 1;
    while (busy) {
      uint32_t status=0;
      if ((res = SQRLAXIRead(fd, &status, 0x120004)) != 0) {
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
	SQRLAXIWrite(fd, (1<<2), 0x120000);
        return 1;
      }
    }

    pos += bytesToSend;
  }
  return 0;
}

static uint64_t eswap64(uint64_t in) {

  return (
           (((in >>  0ULL) & 0xFF) << 56) |
           (((in >>  8ULL) & 0xFF) << 48) |
           (((in >> 16ULL) & 0xFF) << 40) |
           (((in >> 24ULL) & 0xFF) << 32) |
           (((in >> 32ULL) & 0xFF) << 24) |
           (((in >> 40ULL) & 0xFF) << 16) |
           (((in >> 48ULL) & 0xFF) <<  8) |
           ((in >> 56ULL) & 0xFF)
         );
}
static uint32_t eswap32(uint32_t in) {
  return (
           (((in >> 0) & 0xFF) << 24) |
           (((in >> 8) & 0xFF) << 16) |
           (((in >>16) & 0xFF) <<  8) |
           ((in >>24) & 0xFF)
         );
}

/* ################## OS-specific functions ################## */

/*
 * returns physically available memory (no swap)
 */
static size_t getTotalPhysAvailableMemory()
{
  return 8*1024*1024*1024ULL;
}

/*
 * return numbers of available CPUs
 */
unsigned SQRLMiner::getNumDevices(SQSettings _settings)
{
  return _settings.hosts.size(); // Hosts are manually assigned 
}


/* ######################## CPU Miner ######################## */

struct SQRLChannel : public LogChannel
{
    static const char* name() { return EthOrange "sq"; }
    static const int verbosity = 2;
};
#define sqrllog clog(SQRLChannel)


SQRLMiner::SQRLMiner(unsigned _index, SQSettings _settings, DeviceDescriptor& _device)
  : Miner("sqrl-", _index), m_settings(_settings)
{
    m_deviceDescriptor = _device;
}


SQRLMiner::~SQRLMiner()
{
    DEV_BUILD_LOG_PROGRAMFLOW(sqrllog, "sq-" << m_index << " SQRLMiner::~SQRLMiner() begin");
    stopWorking();
    kick_miner();
    DEV_BUILD_LOG_PROGRAMFLOW(sqrllog, "sq-" << m_index << " SQRLMiner::~SQRLMiner() end");

    // Close socket
    if (m_socket != 0) {
      sqrllog << "Disconnecting " << m_deviceDescriptor.name;
      shutdown(m_socket, SHUT_RDWR);
      close(m_socket);
    }
}


bool SQRLMiner::initDevice()
{
    DEV_BUILD_LOG_PROGRAMFLOW(sqrllog, "sq-" << m_index << " SQRLMiner::initDevice begin");

    sqrllog << "Using FPGA: " << m_deviceDescriptor.name
           << " Memory : " << dev::getFormattedMemory((double)m_deviceDescriptor.totalMemory);
    m_hwmoninfo.deviceType = HwMonitorInfoType::SQRL;

    // Open Socket
    int ret=0;
    int fd = 0;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(m_deviceDescriptor.sqPort);
    ret = inet_pton(AF_INET, m_deviceDescriptor.sqHost.c_str(), &server_addr.sin_addr);
    if (ret != 1) {
      if (ret == -1) {
        perror("inet_pton");
      }
      fprintf(stderr,"failed to convert address %s to binary net address\n", m_deviceDescriptor.sqHost.c_str());
      return -1;
    }

    sqrllog << "Connecting " << m_deviceDescriptor.name << "...";
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
      perror("socket");
      return -1;
    }

    int yes = 1;
    ret = setsockopt(fd,IPPROTO_TCP, TCP_NODELAY, (const char *)&yes, sizeof(int));
    if (ret != 0) {
      perror("NODELAY");
      return -1;
    }

    ret = connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret == -1) {
      perror("connect");
      return -1;
    }

    if (fd != 0) {
      sqrllog << m_deviceDescriptor.name << " Connected";
      m_socket = fd;

      // Critical Data
      uint32_t dnaLo,dnaMid,dnaHi;
      SQRLAXIRead(m_socket, &dnaLo, 0x1000);
      SQRLAXIRead(m_socket, &dnaMid, 0x1008);
      SQRLAXIRead(m_socket, &dnaHi, 0x7000);
      std::stringstream s;
      s << setfill('0') << setw(8) << std::hex << dnaLo << std::hex << dnaMid << std::hex << dnaHi;
      sqrllog << "DNA: " << s.str();

      uint32_t device, bitstream;
      SQRLAXIRead(m_socket, &device, 0x0);
      SQRLAXIRead(m_socket, &bitstream, 0x8);
      s.str("");
      s.clear();
      s << (char)(device >> 24) << (char)((device >> 16)&0xff) << (char)((device >> 8)&0xff) << (char)((device >> 0)&0xff);
      sqrllog << "FPGA: " << s.str();
      s.str("");
      s.clear();
      s << setfill('0') << setw(8) << std::hex << bitstream;
      sqrllog << "Bitstream: " << s.str();

      // Initialize clk
      sqrllog << "Stock Clock: " << setClock(-2);
      if ( m_deviceDescriptor.targetClk != 0) {
        sqrllog << "Target Clock: " << m_deviceDescriptor.targetClk; 
	// Target Clock set after Dag Generation
	m_lastClk = m_deviceDescriptor.targetClk;
      } else {
        m_lastClk = getClock();
      }
    } else {
      sqrllog << m_deviceDescriptor.name << " Failed to Connect";
      m_socket = 0;
    }

    DEV_BUILD_LOG_PROGRAMFLOW(sqrllog, "sq-" << m_index << " SQRLMiner::initDevice end");
    return (m_socket != 0);
}


/*
 * A new epoch was receifed with last work package (called from Miner::initEpoch())
 *
 * If we get here it means epoch has changed so it's not necessary
 * to check again dag sizes. They're changed for sure
 * We've all related infos in m_epochContext (.dagSize, .dagNumItems, .lightSize, .lightNumItems)
 */
bool SQRLMiner::initEpoch_internal()
{
    // TODO - Update and recalc DAG
    // Do DAG Stuff!
    // m_epochContext.lightSize
    // m_epochContext.dagSize
    // m_epochContext.lightCache
    
    m_dagging = true;   
    axiMutex.lock();
    sqrllog << "Changing to Epoch " << m_epochContext.epochNumber; 
    // Stop the mining core if it is active, and stop DAGGEN if active
    SQRLAXIWrite(m_socket, 0x0, 0x506c);
    // Ensure DAGGEN is powered on
    SQRLAXIWrite(m_socket, 0xFFFFFFFF, 0xB000);
    // Stop DAGGEN
    SQRLAXIWrite(m_socket, 0x2, 0x4000);

    uint8_t err = 0;

    // Compute and set mining parameters always (DAG may be generated, but core may have been reset)
    uint32_t nItems = m_epochContext.dagSize/128;
    err = SQRLAXIWrite(m_socket, nItems, 0x5040);
    if (err != 0) sqrllog << "Failed setting ethcore nItems";

    // Compute the reciprical, adjusted to ETH optimized modulo
    double reciprical = 1.0/(double)nItems * 0x1000000000000000ULL;
    uint32_t intR = (uint64_t)reciprical >> 4ULL;
    err = SQRLAXIWrite(m_socket, intR, 0x5088);
    if (err != 0) sqrllog << "Failed setting ethcore rnItems!";

    // Check for the existing DAG
    uint32_t dagStatusWord = 0;
    err = SQRLAXIRead(m_socket, &dagStatusWord, 0x40B8);
    if (dagStatusWord >> 31) {
      sqrllog << "Current HW DAG is for Epoch " << (dagStatusWord & 0xFFFF);
      if ((dagStatusWord & 0xFFFF) == (uint32_t)m_epochContext.epochNumber) {
        sqrllog << "No DAG Generation is needed";
	// Power off DAGGEN
	SQRLAXIWrite(m_socket, 0x0, 0xB000);
	m_dagging = false;
	axiMutex.unlock();
	setClock(m_lastClk);
	return true;
      }
    }

    // Reset clock to defaults
    double curClk = getClock();
    if (curClk < m_lastClk) {
      sqrllog << "Resetting clock to Bitstream Default for Dag Generation";
      //m_lastClk = getClock();
      setClock(-2);
    } else {
      setClock(m_lastClk);
    }

    // Newer-bitstreams support on-module cache generation
    const bool makeCacheOnChip = true;
    uint32_t num_parent_nodes = m_epochContext.lightSize/64;
    if (makeCacheOnChip) {
      sqrllog << "Generating LightCache...";
      auto startCache = std::chrono::steady_clock::now(); 
      SQRLAXIWrite(m_socket, 0x2, 0x40BC);
      SQRLAXIWrite(m_socket, num_parent_nodes, 0x4008);
      // Set seedhash (reverse byte order)
      uint8_t revSeed[32];
      uint8_t * newSeed = (uint8_t *)&m_epochContext.seed;
      for(int s=0; s < 32; s++) revSeed[s] = newSeed[31-s];
      //for(int s=0;s<32;s++) printf("%02hhx", revSeed[s]);
      //  printf("\n");
      _SQRLAXIWriteBulk(m_socket, revSeed, 32, 0x40c0, 1/*EndianFlip*/);
      SQRLAXIWrite(m_socket, 0x1, 0x40BC);
      uint32_t cstatus = 0;
      while ((cstatus&2) != 0x2) {
	axiMutex.unlock();
        usleep(100000);
	axiMutex.lock();
        SQRLAXIRead(m_socket, &cstatus, 0x40BC);
      }
      auto cacheTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startCache);
      sqrllog << "Final LightCache Generation Status: " << cstatus;
      sqrllog << "LightCache Generation took " << cacheTime.count() << " ms.";
    } else {
      sqrllog << "Uploading new Light Cache...(This may take some time)";
      auto uploadStart = std::chrono::steady_clock::now(); 
      uint8_t uploadFailed = 0;
      uint32_t cacheSize = m_epochContext.lightSize;
      uint8_t * cache = (uint8_t *)m_epochContext.lightCache;
      uint32_t chunkSize = 65536;
      uint32_t steps=0;
      for(uint32_t pos=0x00; pos < cacheSize; pos+=chunkSize) {
          if (SQRLAXICDMAWriteBytes(m_socket,cache+pos, (cacheSize-pos)>chunkSize?chunkSize:(cacheSize-pos), pos) != 0) {
            sqrllog << "Upload packet error, retrying...";
            if (SQRLAXICDMAWriteBytes(m_socket,cache+pos, (cacheSize-pos)>chunkSize?chunkSize:(cacheSize-pos), pos) != 0) {
              uploadFailed = 1;
              break;
            }
          }
	  if (steps++ % 100 == 0)
            sqrllog << "Cache upload " << (double)(pos+chunkSize)/(double)m_epochContext.lightSize * 100.0 << "%"; 
      }
      if (uploadFailed) {
        sqrllog <<  "Cache upload failed";
      } else {
        auto uploadTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - uploadStart);
        sqrllog << dev::getFormattedMemory((double)m_epochContext.lightSize)
            << " of cache uploaded in "
            << uploadTime.count() << " ms.";
      }
      if (uploadFailed) {
        m_dagging = false;
	axiMutex.unlock();
        return false;
      }
    }
    sqrllog << "Preparing new DAG Generator Parameters...";
    sqrllog << "NUM_PARENT_NODES = " << num_parent_nodes;
    uint32_t num_mixers=16; // This is fixed at bitstream gen time
    sqrllog << "NUM_MIXERS = "<< num_mixers;
    uint32_t mixer_size = m_epochContext.dagSize/64/num_mixers;
    uint32_t leftover = (m_epochContext.dagSize/64 - mixer_size*num_mixers);
    sqrllog << "DAG_ITEMS_PER_MIXER = " << mixer_size;
    sqrllog << "DAG_ITEMS_LEFTOVER = " << leftover;

    SQRLAXIWrite(m_socket, num_parent_nodes, 0x4008);
    uint32_t dagPos=0;
    for(uint32_t i=0; i < num_mixers; i++) {
      uint32_t mixer_start  = dagPos;
      SQRLAXIWrite(m_socket, mixer_start, 0x400c + 8*i);
      uint32_t mixer_end = dagPos+mixer_size;
      if (i == 0) mixer_end += leftover;
      SQRLAXIWrite(m_socket, mixer_end, 0x4010 + 8*i);
      dagPos = mixer_end;
    }

    // Finally, kick off DAG generation
    sqrllog << "Generating DAG...";
    auto startInit = std::chrono::steady_clock::now(); 
    SQRLAXIWrite(m_socket, 0x1, 0x4000);
    uint32_t status;
    SQRLAXIRead(m_socket, &status, 0x4000);
    uint8_t cnt = 0;
    while ((status&2) != 0x2) {
      axiMutex.unlock();
      usleep(100000);
      axiMutex.lock();
      SQRLAXIRead(m_socket, &status, 0x4000);
      cnt++;
      if (cnt % 64 == 0) {
	uint32_t dagProgress = 0;
	SQRLAXIRead(m_socket, &dagProgress, 0x4008);
	double progress = (double)(mixer_size+leftover);
	progress = (double)dagProgress / progress;
        sqrllog << EthPurple << "DAG " << std::fixed << std::setprecision(2) << (progress * 100.0) << "%" << EthReset; 
      }
    }
    sqrllog << "Final DAG Generation Status: " << status;
    auto dagTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startInit);
        sqrllog << dev::getFormattedMemory((double)m_epochContext.dagSize)
              << " of DAG data generated in "
              << dagTime.count() << " ms."; 

    sqrllog << "Duplicating DAG Items for performance...";
    auto startSwizzle = std::chrono::steady_clock::now(); 
    for(uint64_t i=0; i < 256; i++) {
      uint64_t src = 0x100000000ULL | (i << 24);
      uint64_t dst = 0x0ULL | (((i&0x0f) << 4) | ((i&0xF0) >> 4)) << 24;
      //printf("Swizzling chunk from %016lx to %016lx\n", src, dst);
      err = SQRLAXICDMACopyBytes(m_socket, src, dst, 0x1000000ULL);

      if (err != 0) {
        sqrllog << "Failed to swizzle DAG!";
        break;
      } else {
        //printf("Swizzled DAG successfully!\n");
      }
    }
    if (err == 0) {
      //printf("Copying Swizzled DAG back to stack 1...\n");
      err = SQRLAXICDMACopyBytes(m_socket, 0x0ULL, 0x100000000ULL, 4ULL*1024ULL*1024ULL*1024ULL);
      if (err != 0) {
        sqrllog << "Failed to copy DAG!";
      } 
    }
    auto swizzleTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startSwizzle);
    sqrllog << "DAG Duplication took " << swizzleTime.count() << " ms.";

    // Preserve the status to avoid the work in the future
    SQRLAXIWrite(m_socket, (1 << 31) | (uint32_t)m_epochContext.epochNumber, 0x40B8);	
    m_dagging = false;

    sqrllog << "Putting DAG Generator in low power mode...";
    SQRLAXIWrite(m_socket, 0x0, 0xB000);

    if (m_lastClk != 0) {
      sqrllog << "Restoring clock to target of " << (int)m_lastClk;
      setClock(m_lastClk);
    }

    axiMutex.unlock();
    return true;
}


/*
   Miner should stop working on the current block
   This happens if a
     * new work arrived                       or
     * miner should stop (eg exit ethminer)   or
     * miner should pause
*/
void SQRLMiner::kick_miner()
{
    m_new_work.store(true, std::memory_order_relaxed);
    // Just put the core in reset
    if (!m_dagging) {
      // This can happen on odd thread
      //SQRLAXIWrite(m_socket, 0x0, 0x506c);
    }
    m_new_work_signal.notify_one();
}


void SQRLMiner::search(const dev::eth::WorkPackage& w)
{
    const auto& context = ethash::get_global_epoch_context_full(w.epoch);
    const auto header = ethash::hash256_from_bytes(w.header.data());
    const auto boundary = ethash::hash256_from_bytes(w.boundary.data());
    auto nonce = w.startNonce;


    m_new_work.store(false, std::memory_order_relaxed);

    // Re-init parameters 
    axiMutex.lock();
    uint8_t err = 0;
    err = _SQRLAXIWriteBulk(m_socket, (uint8_t *)w.header.data(), 32, 0x5000, 1); 
    if (err != 0) sqrllog << "Failed setting ethcore header";
    err = _SQRLAXIWriteBulk(m_socket, (uint8_t *)w.boundary.data(), 32, 0x5020, 1);
    if (err != 0) sqrllog << "Failed setting ethcore target";
    uint32_t nonceStartHigh = nonce >> 32;
    uint32_t nonceStartLow = nonce & 0xFFFFFFFF;
    err = SQRLAXIWrite(m_socket, nonceStartHigh, 0x5068);
    if (err != 0) sqrllog << "Failed setting ethcore nonceStartHigh";
    err = SQRLAXIWrite(m_socket, nonceStartLow, 0x5064);
    if (err != 0) sqrllog << "Failed setting ethcore nonceStartLow";

    uint32_t flags = 0;
    if (m_settings.patience != 0) {
      flags |= (1 << 6) | ((m_settings.patience & 0xff) << 8); 
    }
    if (m_settings.intensityN != 0) {
      flags |= (1 << 0) | ((m_settings.intensityN & 0xFF) << 24);
      flags |= (((m_settings.intensityD & 0x3F)*8 -1) << 16);
    }
    err = SQRLAXIWrite(m_socket, flags, 0x5080);
    if (err != 0) sqrllog << "Failed setting ethcore debugFlags";
 
    // Esnure hashcore loads new, reset work
    SQRLAXIWrite(m_socket, 0x00000000, 0x506c);
    SQRLAXIWrite(m_socket, 0x00010000, 0x506c);

    uint32_t lastSCnt = 0;
    uint64_t lastTChecks = 0;
    while (true)
    {
        if (m_new_work.load(std::memory_order_relaxed))  // new work arrived ?
        {
            m_new_work.store(false, std::memory_order_relaxed);
            break;
        }

        if (shouldStop())
            break;

	//   auto r = ethash::search(context, header, boundary, nonce, blocksize);
	axiMutex.unlock();
	usleep(m_settings.workDelay); // Give a momment for solutions
	axiMutex.lock();
	uint32_t value = 0;
	bool nonceValid[4] = {false,false,false,false};
	uint64_t nonce[4] = {0,0,0,0};
	uint32_t nonceLo,nonceHi;
	err = SQRLAXIRead(m_socket, &value, 0x506c);
        if (err != 0) sqrllog << "Failed checking nonceFlags";
	if ((value >> 15) & 0x1) {
           nonceValid[0] = true;
	   SQRLAXIRead(m_socket, &nonceHi, 0x5000+19*4);
	   SQRLAXIRead(m_socket, &nonceLo, 0x5000+28*4);
	   nonce[0] = ((((uint64_t)nonceHi) << 32ULL) | (uint64_t)nonceLo);
	} else nonceValid[0] = false;
	if ((value >> 14) & 0x1) {
           nonceValid[1] = true;
	   SQRLAXIRead(m_socket, &nonceHi, 0x5000+20*4);
	   SQRLAXIRead(m_socket, &nonceLo, 0x5000+29*4);
	   nonce[1] = ((((uint64_t)nonceHi) << 32ULL) | (uint64_t)nonceLo);
	} else nonceValid[1] = false;
	if ((value >> 13) & 0x1) {
           nonceValid[2] = true;
	   SQRLAXIRead(m_socket, &nonceHi, 0x5000+21*4);
	   SQRLAXIRead(m_socket, &nonceLo, 0x5000+30*4);
	   nonce[2] = ((((uint64_t)nonceHi) << 32ULL) | (uint64_t)nonceLo);
	} else nonceValid[2] = false;
	if ((value >> 12) & 0x1) {
           nonceValid[3] = true;
	   SQRLAXIRead(m_socket, &nonceHi, 0x5000+22*4);
	   SQRLAXIRead(m_socket, &nonceLo, 0x5000+31*4);
	   nonce[3] = ((((uint64_t)nonceHi) << 32ULL) | (uint64_t)nonceLo);
	} else nonceValid[3] = false;
	// Clear nonces if needed
	if (nonceValid[0] || nonceValid[1] || nonceValid[2] || nonceValid[3]) {
	  SQRLAXIWrite(m_socket, 0x00010000, 0x506c);
	}

        // Get stall check parameters
	uint32_t sCnt;
	uint32_t tChkLo, tChkHi;
	if (!m_settings.skipStallDetection) {
          SQRLAXIRead(m_socket, &sCnt, 0x5084);
	}
	SQRLAXIRead(m_socket, &tChkLo, 0x5048);
	SQRLAXIRead(m_socket, &tChkHi, 0x5044);
	uint64_t tChks = ((uint64_t)tChkHi << 32) + tChkLo;
	if (tChks < lastTChecks) tChkHi++; // Cheap rollover detection
	uint64_t newTChks = tChks - lastTChecks;
	lastTChecks = tChks; 
	uint8_t shouldReset = 0;
	if (!m_settings.skipStallDetection && (sCnt == lastSCnt)) {
          // Reset the core, re-init nonceStart 
	  shouldReset = 1;
	}
	lastSCnt = sCnt;

	for (int i=0; i < 4; i++) {
          if (nonceValid[i]) {
	    auto r = ethash::search(context, header, boundary, nonce[i], 1);
	    if (r.solution_found) {
              h256 mix{reinterpret_cast<byte*>(r.mix_hash.bytes), h256::ConstructFromPointer};
              auto sol = Solution{r.nonce, mix, w, std::chrono::steady_clock::now(), m_index};
 
              sqrllog << EthWhite << "Job: " << w.header.abridged()
                   << " Sol: " << toHex(sol.nonce, HexPrefix::Add) << EthReset;
              Farm::f().submitProof(sol);
	    } else {
	      sqrllog << EthRed << "Could not validate FPGA solution";
	    }
	  }
	}

        // Update the hash rate
        updateHashRate(newTChks, 1);
	if (shouldReset) break; // Let core reset
    }
    // Ensure core is in reset
    SQRLAXIWrite(m_socket, 0x0, 0x506c);
    axiMutex.unlock();
}

double SQRLMiner::getClock() {
  return setClock(-1);
}

double SQRLMiner::setClock(double targetClk) {
  uint32_t valueVCO;
  SQRLAXIRead(m_socket, &valueVCO, 0x8200);
  double mult = (double)((valueVCO>>8) &0xFF);
  double frac = 0;
  if ((valueVCO >> 16) & 0x2F) {
     frac = ((double)((valueVCO >> 16) & 0x3FF)) / 1000;
  }
  double gdiv = (valueVCO & 0xF);
  double vco = 200.0 * (mult+frac);
  vco /= gdiv;

  uint32_t valueClk0;
  SQRLAXIRead(m_socket, &valueClk0, 0x8208);
  double clk0div = (double)(valueClk0 & 0xF);
  double clk0FracDiv = ((double)((valueClk0 >> 8) & 0x3FF))/1000;
  clk0div += clk0FracDiv;

  double currentClk = vco / clk0div;

  // Changing?
  uint32_t nItems,rnItems;
  uint32_t daggenPwrState;
  if (targetClk != -1.0) {
    // Make sure we backup mining parameters - clock unlock can reset these
    SQRLAXIRead(m_socket, &nItems, 0x5040);
    SQRLAXIRead(m_socket, &rnItems, 0x5088);
    // Ensure DAGGEN is powered on
    SQRLAXIRead(m_socket, &daggenPwrState, 0xB000);   
    SQRLAXIWrite(m_socket, 0xFFFFFFFF, 0xB000);   
  }
  if (targetClk > 0) {
    double desiredDiv = vco/targetClk;
    // Adjust to be multiple of 0.125 (round up == closed without going over
    desiredDiv = ((double)((int)(desiredDiv * 8 + 0.99))) / 8.0;
    if (desiredDiv < 2.0) {
      // Over max clock
      sqrllog << "CoreClk would exceed limit"; 
    } else {
      uint32_t newDiv = ((uint8_t)desiredDiv) | ((uint16_t)((desiredDiv-floor(desiredDiv))*1000.0) << 8);
      SQRLAXIWrite(m_socket, newDiv, 0x8208);
      SQRLAXIWrite(m_socket, 0x7, 0x825c);
      SQRLAXIWrite(m_socket, 0x3, 0x825c);
      currentClk = vco/desiredDiv;
      sqrllog << "Setting CoreClk to " << (int)currentClk;
    }
  } else if (targetClk < -1.0) {
    sqrllog << "Resetting CoreClk to Stock";
    // Reset to factory defaults
    SQRLAXIWrite(m_socket, 0x5, 0x825c);
    SQRLAXIWrite(m_socket, 0x1, 0x825c);
    usleep(10000);
    SQRLAXIWrite(m_socket, 0xA, 0x8000);
  }
  if (targetClk != -1.0) {
    // Wait for locked
    uint32_t waitCnt=1000;
    while(waitCnt--) {
      uint32_t locked;
      SQRLAXIRead(m_socket, &locked, 0x8004);
      if (locked&1) break;
    }

    // Make sure we restore the mining parameters 
    SQRLAXIWrite(m_socket, nItems, 0x5040);
    SQRLAXIWrite(m_socket, rnItems, 0x5088);
    SQRLAXIWrite(m_socket, daggenPwrState, 0xB000);
  }
  return currentClk;
}

void SQRLMiner::getTelemetry(unsigned int *tempC, unsigned int *fanprct, unsigned int *powerW) {
  // Temp Conversion: 
  // ((double)raw * 507.6 / 65536.0) - 279.43;
  // Volt Conversion
  // ((double)raw * 3.0 / 65536.0);

  // Read general SYSMON temp 
  axiMutex.lock();
  uint32_t raw;
  SQRLAXIRead(m_socket, &raw, 0x3400);
  (*tempC) = ((double)raw * 507.6 / 65536.0) - 279.43;
  (*fanprct) = getClock(); 
  SQRLAXIRead(m_socket, &raw, 0x3404);
  (*powerW) = ((double)raw * 3.0 / 65536.0) * 1000.0;
  axiMutex.unlock();
} 


/*
 * The main work loop of a Worker thread
 */
void SQRLMiner::workLoop()
{
    DEV_BUILD_LOG_PROGRAMFLOW(sqrllog, "sq-" << m_index << " SQRLMiner::workLoop() begin");

    WorkPackage current;
    current.header = h256();

    if (!initDevice())
        return;

    while (!shouldStop())
    {
        // Wait for work or 3 seconds (whichever the first)
        const WorkPackage w = work();
        if (!w)
        {
            boost::system_time const timeout =
                boost::get_system_time() + boost::posix_time::seconds(3);
            boost::mutex::scoped_lock l(x_work);
            m_new_work_signal.timed_wait(l, timeout);
            continue;
        }

        if (w.algo == "ethash")
        {
            // Epoch change ?
            if (current.epoch != w.epoch)
            {
                if (!initEpoch())
                    break;  // This will simply exit the thread

                // As DAG generation takes a while we need to
                // ensure we're on latest job, not on the one
                // which triggered the epoch change
                current = w;
                continue;
            }

            // Persist most recent job.
            // Job's differences should be handled at higher level
            current = w;

            // Start searching
            search(w);
        }
        else
        {
            throw std::runtime_error("Algo : " + w.algo + " not yet implemented");
        }
    }

    DEV_BUILD_LOG_PROGRAMFLOW(sqrllog, "sq-" << m_index << " SQRLMiner::workLoop() end");
}


void SQRLMiner::enumDevices(std::map<string, DeviceDescriptor>& _DevicesCollection, SQSettings _settings)
{
    unsigned numDevices = getNumDevices(_settings);

    for (unsigned i = 0; i < numDevices; i++)
    {
        string uniqueId;
        ostringstream s;
        DeviceDescriptor deviceDescriptor;

        s << "sqrl-" << i;
        uniqueId = s.str();
        if (_DevicesCollection.find(uniqueId) != _DevicesCollection.end())
            deviceDescriptor = _DevicesCollection[uniqueId];
        else
            deviceDescriptor = DeviceDescriptor();

        std::vector<std::string> words;
        boost::split(words, _settings.hosts[i], boost::is_any_of(":"), boost::token_compress_on);

	deviceDescriptor.sqHost = words[0];
	deviceDescriptor.sqPort = (words.size() > 1)?stoi(words[1]):2000;

        s.str("");
        s.clear();
        s << "SQRL TCP-FPGA (" << deviceDescriptor.sqHost << ":" << deviceDescriptor.sqPort << ")" ;
        deviceDescriptor.name = s.str();
        deviceDescriptor.uniqueId = uniqueId;
        deviceDescriptor.type = DeviceTypeEnum::Fpga;
        deviceDescriptor.totalMemory = getTotalPhysAvailableMemory();
	deviceDescriptor.targetClk = _settings.targetClk;

        _DevicesCollection[uniqueId] = deviceDescriptor;
    }
}
