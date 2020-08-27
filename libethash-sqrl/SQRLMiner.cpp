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


#include "SQRLAXI.h"

using namespace std;
using namespace dev;
using namespace eth;

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


SQRLMiner::SQRLMiner(unsigned _index, SQSettings _settings, DeviceDescriptor& _device, TelemetryType* telemetry)
  : Miner("sqrl-", _index), m_settings(_settings), _telemetry(telemetry)
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
    if (m_axi != 0) {
      sqrllog << "Disconnecting " << m_deviceDescriptor.name;
      SQRLAXIDestroy(&m_axi);
    }
}


bool SQRLMiner::initDevice()
{
    DEV_BUILD_LOG_PROGRAMFLOW(sqrllog, "sq-" << m_index << " SQRLMiner::initDevice begin");

    sqrllog << "Using FPGA: " << m_deviceDescriptor.name
           << " Memory : " << dev::getFormattedMemory((double)m_deviceDescriptor.totalMemory);
    m_hwmoninfo.deviceType = HwMonitorInfoType::SQRL;

    SQRLAXIRef axi = SQRLAXICreate(SQRLAXIConnectionTCP, (char *)m_deviceDescriptor.sqHost.c_str(), m_deviceDescriptor.sqPort);
    if (axi != NULL) {
      sqrllog << m_deviceDescriptor.name << " Connected";
      m_axi = axi;

      // Critical Data
      uint32_t dnaLo,dnaMid,dnaHi;
      SQRLAXIRead(m_axi, &dnaLo, 0x1000);
      SQRLAXIRead(m_axi, &dnaMid, 0x1008);
      SQRLAXIRead(m_axi, &dnaHi, 0x7000);
      std::stringstream s;
      s << setfill('0') << setw(8) << std::hex << dnaLo << std::hex << dnaMid << std::hex << dnaHi;
      sqrllog << "DNA: " << s.str();

      uint32_t device, bitstream;
      SQRLAXIRead(m_axi, &device, 0x0);
      SQRLAXIRead(m_axi, &bitstream, 0x8);
      s.str("");
      s.clear();
      s << (char)(device >> 24) << (char)((device >> 16)&0xff) << (char)((device >> 8)&0xff) << (char)((device >> 0)&0xff);
      sqrllog << "FPGA: " << s.str();
      s.str("");
      s.clear();
      s << setfill('0') << setw(8) << std::hex << bitstream;
      sqrllog << "Bitstream: " << s.str();

      // Set voltage if asked
      if (m_settings.fkVCCINT > 500) {
	double r1           = 1.0 / (1.0 / 8.87 + 1.0 / 8.87); // R101 || R29
        double r2           = 20.0; // R30
	double rSeries      = 10.0; // R81
	double rRheostatMax = 50.0; // +- 20%
	uint8_t tWiper=0x44;
	unsigned tmv=850;
	for(uint8_t wiperCode=0; wiperCode < 0xFF; wiperCode++) {
	  double r2Adj = 1.0 / ((1.0 / r2) + (1.0 / (rSeries + (rRheostatMax / 256.0 * (double)(wiperCode)))));
	  double v = 0.6 * (1.0 + (r1 / r2Adj));
	  if ((v * 1000) >= m_settings.fkVCCINT) {
            tWiper = wiperCode;
	    tmv = (v*1000);
	  }
	}
        sqrllog << "Instructing FK VRM, if present, to target " << m_settings.fkVCCINT << "mv";
        sqrllog << "Closest Viable Voltage " << tmv << "mv";
        SQRLAXIWrite(m_axi, 0xA, 0x9040, false); 	
        SQRLAXIWrite(m_axi, 0x158, 0x9108, false); 	
        SQRLAXIWrite(m_axi, 0x00, 0x9108, false); 	
        SQRLAXIWrite(m_axi, 0x200 | tWiper, 0x9108, false); 	
        SQRLAXIWrite(m_axi, 0x1, 0x9100, false); 	
      }
      if (m_settings.jcVCCINT > 500) {
        sqrllog << "Asking JCM VRM, if present, to target " << m_settings.jcVCCINT << "mv";

        uint16_t vEnc = (uint16_t)(((double)m_settings.jcVCCINT/1000.0) * 256.0);
        SQRLAXIWrite(m_axi, 0xA, 0xA040, false); // Soft Reset IIC 	
        SQRLAXIWrite(m_axi, 0x100|(0x4d<<1), 0xA108, false); // Transmit FIFO byte 1 (Write(startbit), Addr, Acadia) 	
        SQRLAXIWrite(m_axi, 0xD0, 0xA108, false); // Transmit FIFO byte 2 (SingleShotPage+Cmd)
        SQRLAXIWrite(m_axi, 0x04, 0xA108, false); // Transmit FIFO byte 3 (Write)
        SQRLAXIWrite(m_axi, (0x21 << 1), 0xA108, false); // Transmit FIFO byte 4 (AddrLo (CMD)	
        SQRLAXIWrite(m_axi, 0x06, 0xA108, false); // Transmit FIFO byte 2, VOUT CMD 
        SQRLAXIWrite(m_axi, 0x0 | (vEnc & 0xFF), 0xA108, false); // Transmit FIFO byte 3 // vEnc[0]
        SQRLAXIWrite(m_axi, 0x200 | ((vEnc >> 8) & 0xFF), 0xA108, false); // Transmit FIFO byte 4 // vEnc[1] (With Stop)
        SQRLAXIWrite(m_axi, 0x1, 0xA100, false); // Send IIC transaction 	
      }

      // Initialize clk
      sqrllog << "Stock Clock: " << setClock(-2);
      if ( m_deviceDescriptor.targetClk != 0) {
        sqrllog << "Target Clock: " << m_deviceDescriptor.targetClk; 
	// Target Clock set after Dag Generation
	m_lastClk = m_deviceDescriptor.targetClk;
      } else {
        m_lastClk = getClock();
      }
      // Print the settings
      sqrllog << "WorkDelay: " << m_settings.workDelay;
      sqrllog << "Patience: " << m_settings.patience;
      sqrllog << "IntensityN: " << m_settings.intensityN;
      sqrllog << "IntensityD: " << m_settings.intensityD;
      sqrllog << "SkipStallDetect: " << m_settings.skipStallDetection;
    } else {
      sqrllog << m_deviceDescriptor.name << " Failed to Connect";
      m_axi = NULL;
    }

    DEV_BUILD_LOG_PROGRAMFLOW(sqrllog, "sq-" << m_index << " SQRLMiner::initDevice end");
    return (m_axi != 0);
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
    SQRLAXIWrite(m_axi, 0x0, 0x506c, true);
    // Ensure DAGGEN is powered on
    SQRLAXIWrite(m_axi, 0xFFFFFFFF, 0xB000, true);
    // Stop DAGGEN
    SQRLAXIWrite(m_axi, 0x2, 0x4000, true);

    uint8_t err = 0;

    // Compute and set mining parameters always (DAG may be generated, but core may have been reset)
    uint32_t nItems = m_epochContext.dagSize/128;
    err = SQRLAXIWrite(m_axi, nItems, 0x5040, true);
    if (err != 0) sqrllog << "Failed setting ethcore nItems";

    // Compute the reciprical, adjusted to ETH optimized modulo
    double reciprical = 1.0/(double)nItems * 0x1000000000000000ULL;
    uint32_t intR = (uint64_t)reciprical >> 4ULL;
    err = SQRLAXIWrite(m_axi, intR, 0x5088, true);
    if (err != 0) sqrllog << "Failed setting ethcore rnItems!";

    // Check for the existing DAG
    uint32_t dagStatusWord = 0;
    err = SQRLAXIRead(m_axi, &dagStatusWord, 0x40B8);
    if (dagStatusWord >> 31) {
      sqrllog << "Current HW DAG is for Epoch " << (dagStatusWord & 0xFFFF);
      if ( (dagStatusWord & 0xFFFF) == (uint32_t)m_epochContext.epochNumber) {
        sqrllog << "No DAG Generation is needed";
	// Power off DAGGEN
	SQRLAXIWrite(m_axi, 0x0, 0xB000, true);
	m_dagging = false;
	axiMutex.unlock();
	setClock(m_lastClk);

    m_intensitySettings.patience = m_settings.patience;
    m_intensitySettings.intensityD = m_settings.intensityD;
    m_intensitySettings.intensityN = m_settings.intensityN;
    m_lastTuneTime = std::chrono::steady_clock::now();

	return true;
      }
    }

    // Ensure DAGGEN reset if we have to regenerate
    SQRLAXIWrite(m_axi, 0xFFFFFFFD, 0xB000, true);
    SQRLAXIWrite(m_axi, 0xFFFFFFFF, 0xB000, true);

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
      SQRLAXIWrite(m_axi, 0x2, 0x40BC, true);
      SQRLAXIWrite(m_axi, num_parent_nodes, 0x4008, true);
      // Set seedhash (reverse byte order)
      uint8_t revSeed[32];
      uint8_t * newSeed = (uint8_t *)&m_epochContext.seed;
      for(int s=0; s < 32; s++) revSeed[s] = newSeed[31-s];
      //for(int s=0;s<32;s++) printf("%02hhx", revSeed[s]);
      //  printf("\n");
      SQRLAXIWriteBulk(m_axi, revSeed, 32, 0x40c0, 1/*EndianFlip*/);
      SQRLAXIWrite(m_axi, 0x1, 0x40BC, true);
      uint32_t cstatus = 0;
      while ((cstatus&2) != 0x2) {
	axiMutex.unlock();
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
	axiMutex.lock();
        err = SQRLAXIRead(m_axi, &cstatus, 0x40BC);
        if((err != 0) && m_settings.dieOnError) {
          exit(1);
        }
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
          if (SQRLAXICDMAWriteBytes(m_axi,cache+pos, (cacheSize-pos)>chunkSize?chunkSize:(cacheSize-pos), pos) != 0) {
            sqrllog << "Upload packet error, retrying...";
            if (SQRLAXICDMAWriteBytes(m_axi,cache+pos, (cacheSize-pos)>chunkSize?chunkSize:(cacheSize-pos), pos) != 0) {
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
    uint32_t num_mixers=m_settings.dagMixers; // This is fixed at bitstream gen time, added only for convience
    sqrllog << "NUM_MIXERS = "<< num_mixers;
    uint32_t mixer_size = m_epochContext.dagSize/64/num_mixers;
    uint32_t leftover = (m_epochContext.dagSize/64 - mixer_size*num_mixers);
    sqrllog << "DAG_ITEMS_PER_MIXER = " << mixer_size;
    sqrllog << "DAG_ITEMS_LEFTOVER = " << leftover;

    SQRLAXIWrite(m_axi, num_parent_nodes, 0x4008, true);
    uint32_t dagPos=0;
    for(uint32_t i=0; i < num_mixers; i++) {
      uint32_t mixer_start  = dagPos;
      SQRLAXIWrite(m_axi, mixer_start, 0x400c + 8*i, true);
      uint32_t mixer_end = dagPos+mixer_size;
      if (i == 0) mixer_end += leftover;
      SQRLAXIWrite(m_axi, mixer_end, 0x4010 + 8*i, true);
      dagPos = mixer_end;
    }

    // Finally, kick off DAG generation
    sqrllog << "Generating DAG...";
    auto startInit = std::chrono::steady_clock::now(); 
    SQRLAXIWrite(m_axi, 0x1, 0x4000, true);
    uint32_t status;
    SQRLAXIRead(m_axi, &status, 0x4000);
    uint8_t cnt = 0;
    while ((status&2) != 0x2) {
      axiMutex.unlock();
#ifdef _WIN32
      Sleep(1000);
#else
      usleep(1000000);
#endif
      axiMutex.lock();
      err = SQRLAXIRead(m_axi, &status, 0x4000);
      if((err != 0) && m_settings.dieOnError) {
        exit(1);
      }
      cnt++;
      if (cnt % 5 == 0) {
	uint32_t dagProgress = 0;
	SQRLAXIRead(m_axi, &dagProgress, 0x4008);
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
      err = SQRLAXICDMACopyBytes(m_axi, src, dst, 0x1000000ULL);

      if (err != 0) {
        sqrllog << "Failed to swizzle DAG!";
        break;
      } else {
        //printf("Swizzled DAG successfully!\n");
      }
    }
    if (err == 0) {
      //printf("Copying Swizzled DAG back to stack 1...\n");
      err = SQRLAXICDMACopyBytes(m_axi, 0x0ULL, 0x100000000ULL, 4ULL*1024ULL*1024ULL*1024ULL);
      if (err != 0) {
        sqrllog << "Failed to copy DAG!";
      } 
    }
    auto swizzleTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startSwizzle);
    sqrllog << "DAG Duplication took " << swizzleTime.count() << " ms.";

    // Preserve the status to avoid the work in the future
    SQRLAXIWrite(m_axi, (1 << 31) | (uint32_t)m_epochContext.epochNumber, 0x40B8, true);	
    m_dagging = false;

    sqrllog << "Putting DAG Generator in low power mode...";
    SQRLAXIWrite(m_axi, 0x0, 0xB000, true);

    if (m_lastClk != 0) {
      sqrllog << "Restoring clock to target of " << (int)m_lastClk;
      setClock(m_lastClk);
    }

    axiMutex.unlock();

    m_intensitySettings.patience = m_settings.patience;
    m_intensitySettings.intensityD = m_settings.intensityD;
    m_intensitySettings.intensityN = m_settings.intensityN;
    m_lastTuneTime = std::chrono::steady_clock::now();

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
      //SQRLAXIWrite(m_axi, 0x0, 0x506c, false);
    }
    m_new_work_signal.notify_one();
}


void SQRLMiner::search(const dev::eth::WorkPackage& w)
{
    const auto& context = ethash::get_global_epoch_context(w.epoch);
    const auto header = ethash::hash256_from_bytes(w.header.data());
    const auto boundary = ethash::hash256_from_bytes(w.boundary.data());
    auto nonce = w.startNonce;

    

    m_new_work.store(false, std::memory_order_relaxed);

    // Re-init parameters 
    axiMutex.lock();
    uint8_t err = 0;
    err = SQRLAXIWriteBulk(m_axi, (uint8_t *)w.header.data(), 32, 0x5000, 1); 
    if (err != 0) sqrllog << "Failed setting ethcore header";
    auto falseTarget = h256("0x0000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    if (w.boundary > falseTarget) falseTarget = w.boundary;
    err = SQRLAXIWriteBulk(m_axi, (uint8_t*)falseTarget.data(), 32, 0x5020, 1);
    if (err != 0) sqrllog << "Failed setting ethcore target";
    uint32_t nonceStartHigh = nonce >> 32;
    uint32_t nonceStartLow = nonce & 0xFFFFFFFF;
    err = SQRLAXIWrite(m_axi, nonceStartHigh, 0x5068, false);
    if (err != 0) sqrllog << "Failed setting ethcore nonceStartHigh";
    err = SQRLAXIWrite(m_axi, nonceStartLow, 0x5064, false);
    if (err != 0) sqrllog << "Failed setting ethcore nonceStartLow";

    uint32_t flags = 0;
    if (m_intensitySettings.patience != 0)
    {
        flags |= (1 << 6) | ((m_intensitySettings.patience & 0xff) << 8); 
    }
    if (m_intensitySettings.intensityN != 0)
    {
        flags |= (1 << 0) | ((m_intensitySettings.intensityN & 0xFF) << 24);
        flags |= (((m_intensitySettings.intensityD & 0x3F) * 8 - 1) << 16);
    }
    err = SQRLAXIWrite(m_axi, flags, 0x5080, false);
    if (err != 0) {
      sqrllog << "Failed setting ethcore debugFlags";
      if(m_settings.dieOnError) {
        exit(1);
      }
    }
 
    // Esnure hashcore loads new, reset work
    SQRLAXIWrite(m_axi, 0x00000000, 0x506c, false);
    // Bit 0 = enable nonces via interrupt instead of polling
    SQRLAXIWrite(m_axi, 0x00010001, 0x506c, false);

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

	bool nonceValid[4] = {false,false,false,false};
	uint64_t nonce[4] = {0,0,0,0};

	if (0/*Legacy Mode*/) {
	  // LEGACY - polling based
#ifdef _WIN32
	  Sleep(m_settings.workDelay/1000); // Give a momment for solutions
#else
	  usleep(m_settings.workDelay); // Give a momment for solutions
#endif
	  axiMutex.lock();

	  uint32_t value = 0;
	  uint32_t nonceLo,nonceHi;
	  err = SQRLAXIRead(m_axi, &value, 0x506c);
          if (err != 0) sqrllog << "Failed checking nonceFlags";
    	  if ((value >> 15) & 0x1) {
            nonceValid[0] = true;
	    SQRLAXIRead(m_axi, &nonceHi, 0x5000+19*4);
	    SQRLAXIRead(m_axi, &nonceLo, 0x5000+28*4);
	    nonce[0] = ((((uint64_t)nonceHi) << 32ULL) | (uint64_t)nonceLo);
 	  } else nonceValid[0] = false;
	  if ((value >> 14) & 0x1) {
            nonceValid[1] = true;
	    SQRLAXIRead(m_axi, &nonceHi, 0x5000+20*4);
	    SQRLAXIRead(m_axi, &nonceLo, 0x5000+29*4);
	    nonce[1] = ((((uint64_t)nonceHi) << 32ULL) | (uint64_t)nonceLo);
	  } else nonceValid[1] = false;
	  if ((value >> 13) & 0x1) {
            nonceValid[2] = true;
	    SQRLAXIRead(m_axi, &nonceHi, 0x5000+21*4);
	    SQRLAXIRead(m_axi, &nonceLo, 0x5000+30*4);
	    nonce[2] = ((((uint64_t)nonceHi) << 32ULL) | (uint64_t)nonceLo);
	  } else nonceValid[2] = false;
	  if ((value >> 12) & 0x1) {
            nonceValid[3] = true;
	    SQRLAXIRead(m_axi, &nonceHi, 0x5000+22*4);
	    SQRLAXIRead(m_axi, &nonceLo, 0x5000+31*4);
	    nonce[3] = ((((uint64_t)nonceHi) << 32ULL) | (uint64_t)nonceLo);
	  } else nonceValid[3] = false;
	  // Clear nonces if needed
	  if (nonceValid[0] || nonceValid[1] || nonceValid[2] || nonceValid[3]) {
	    SQRLAXIWrite(m_axi, 0x00010000, 0x506c, false);
 	  }
        } else {
          // Modern, interrupt
	  uint64_t interruptNonce;
          SQRLAXIResult axiRes = SQRLAXIWaitForInterrupt(m_axi, 0, &interruptNonce,m_settings.workDelay/1000);  	
	  if (axiRes == SQRLAXIResultOK) {
            nonceValid[0] = true;
	    nonce[0] = interruptNonce;  
	  } else if (axiRes == SQRLAXIResultTimedOut) {
            // Normal
	    nonceValid[0] = false;
	  } else {
	    sqrllog << EthRed << "FPGA Interrupt Error";
	    if(m_settings.dieOnError) {
              exit(1);
	    }
  	  }
	  axiMutex.lock();
	}

        // Get stall check parameters
	uint32_t sCnt;
	uint32_t tChkLo, tChkHi;
	if (!m_settings.skipStallDetection) {
          SQRLAXIRead(m_axi, &sCnt, 0x5084);
	}
	SQRLAXIRead(m_axi, &tChkLo, 0x5048);
	SQRLAXIRead(m_axi, &tChkHi, 0x5044);
	uint64_t tChks = ((uint64_t)tChkHi << 32) + tChkLo;
	if (tChks < lastTChecks) tChkHi++; // Cheap rollover detection
	uint64_t newTChks = tChks - lastTChecks;
	lastTChecks = tChks; 
	uint8_t shouldReset = 0;
	if (!m_settings.skipStallDetection && (sCnt == lastSCnt)) {
          // Reset the core, re-init nonceStart 
	  shouldReset = 1;
	}


	for (int i=0; i < 4; i++) {
          if (nonceValid[i]) {
            auto sol = Solution{nonce[i], h256(0), w, std::chrono::steady_clock::now(), m_index};
 
            sqrllog << EthWhite << "Job: " << w.header.abridged()
                 << " Sol: " << toHex(sol.nonce, HexPrefix::Add) << EthReset;
            Farm::f().submitProof(sol);
	  }
	}
   
        // Update the hash rate
        updateHashRate(newTChks, 1);

        if (m_settings.autoTune > 0)
        {
            autoTune();
            m_hashCounter += tChkLo;
        }

	if (shouldReset) break; // Let core reset
    }
    // Ensure core is in reset
    SQRLAXIWrite(m_axi, 0x0, 0x506c, false);
    axiMutex.unlock();

}
/*
1. Move frequency up until 0 target checks or invalids, then back off one tick (inc 0.125 on divider)
2. Start with ~60%, increase intensity or binary search until you find the local maxima. Do this with patience 1
3. Set patience up by 1, search +/- 2/3 inn values for a new local maxima
4. Repeat until patience makes it worse
*/
void SQRLMiner::autoTune()
{
    //Stage 1:
    int stage1_averageSeconds = 60;
    float stabilityThreshold = 10;  // mhs
    
    //Stage 2:
    float errorRateThreshold = 0.03;  // 3%
    int tuningShareCount = 100;      // how many low shares to check to derive average from

    //Stage 3:
    int stage3_averageSeconds = 60;
    
    

    float hash = RetrieveHashRate();
    float mhs = hash / pow(10, 6);
    auto it = std::find(_freqSteps.begin(), _freqSteps.end(), m_lastClk);
    auto currentStepIndex = std::distance(_freqSteps.begin(), it);

    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - (timePoint)m_lastTuneTime).count();

   
    if (m_settings.autoTune >= 1 && !m_stableFreqFound)  // Stage 1: Do a quick tune to get max frequency
    {
        if (elapsedSeconds > stage1_averageSeconds)
        {
            if (it == _freqSteps.end())
            {
                sqrllog << EthOrange << "S1: Could not find starting index, stopping...";
                return;
            }

            if (mhs > stabilityThreshold)  // assume above threshold mhs -> stable, can try higher
                                           // clock
            {
                if (!m_maxFreqReached)
                {
                    if (currentStepIndex != _freqSteps.size() - 1)  // not getting out of bounds
                    {
                        int nextClock =
                            _freqSteps[currentStepIndex + 1] + 1;  //+1 for precision issues
                        sqrllog << EthOrange<< "S1: Stable at " << m_lastClk << "MHz, trying " << nextClock - 1 << "...";
                        setClock(nextClock);
                        m_lastClk = nextClock - 1;
                    }
                    else
                    {
                        sqrllog << EthOrange<< "Clocking out of bounds, max frequency reached!";
                        m_maxFreqReached = true;
                    }
                }
            }
            else  // Unstable, downclock...
            {
                m_maxFreqReached = true;
                if (currentStepIndex > 0)
                {
                    int nextClock = _freqSteps[currentStepIndex - 1] + 1;  //+1 for precision issues
                    sqrllog << EthOrange <<"S1: Unstable at " << m_lastClk << "MHz, downclocking to "
                            << nextClock - 1 << "...";
                    setClock(nextClock);
                    m_lastClk = nextClock - 1;

                    clearSolutionStats();
                }
                else
                    sqrllog << EthOrange<< "S1: Clocking out of bounds, min frequency reached!";
            }


            m_lastTuneTime = std::chrono::steady_clock::now();
        }
    }
    if (m_settings.autoTune >= 2)// Stage 2: Check for long term stability and error rate (removes marginally stable)
    {
        
        if (m_maxFreqReached && !m_stableFreqFound)
        {
            // calculate error rate
            SolutionAccountType solutions = getSolutions();

            if (solutions.low > 0 && (solutions.low+solutions.failed) % tuningShareCount == 0)
            {
                float errorRate = (float)solutions.failed / (solutions.low + solutions.failed);

                if (errorRate > errorRateThreshold)
                {
                    sqrllog << EthOrange<< "S2: Error rate of " << errorRate * 100 << "% above threshold (" << errorRateThreshold * 100 << "%), downclocking...";
                    int nextClock = _freqSteps[currentStepIndex - 1] + 1;  //+1 for precision issues
                    setClock(nextClock);
                    m_lastClk = nextClock - 1;

                    clearSolutionStats();
                }
                else
                {
                    sqrllog << EthOrange<< "S2: Stable long term frequency found at " << m_lastClk << "MHz";
                    m_stableFreqFound = true;
                }
            }
        }
    }

    if (m_settings.autoTune >= 3 && !m_intensityTuneFinished)   
    {       
            if (m_stableFreqFound)
            {
                if (!m_intensityTuning)  // init
                {
                    float targetThroughput = _throughputTargets[m_firstPassIndex];
                    m_intensitySettings.patience = 1;
                    m_intensitySettings.intensityD = 8;
                    m_intensitySettings.intensityN =
                        (int)((m_intensitySettings.intensityD * targetThroughput) /
                              (-targetThroughput + 1));  // derive inital N from 60% throughput.

                    clearSolutionStats();
                    m_intensityTuning = true;
                    sqrllog << EthOrange << "S3: Intensity tuning started... init settings ->"
                            << m_intensitySettings.to_string();

                    m_lastTuneTime = std::chrono::steady_clock::now();
                }
                else
                {
                    if (elapsedSeconds > stage3_averageSeconds)
                    {
                        float errorRate = getHardwareErrorRate();

                        float throughput =
                            (float)m_intensitySettings.intensityN /
                            (m_intensitySettings.intensityN + m_intensitySettings.intensityD);

                        pair<IntensitySettings, double> p;

                        double adjustedHash = m_hashCounter * (1 - errorRate);
                        p = std::make_pair(m_intensitySettings, adjustedHash);  // penalize for
                                                                                // producing errors

                        if (m_bestSettingsSoFar.second < adjustedHash)
                            m_bestSettingsSoFar = p;

                        m_shareTimes.push_back(p);
                        sqrllog << EthOrange << "S3: [" << m_intensitySettings.to_string()
                                << "] errorRate=" << errorRate
                                << " Hashrate=" << m_hashCounter / stage3_averageSeconds
                                << " throughput=" << throughput * 100 << "%";


                       

                          if (!m_bestIntensityRangeFound)  // Stage 3.1: Tune intensity, find best range
                            {
                              if (m_secondPassLowerN == 0 &&
                                  m_secondPassUpperN == 0)  // still first coarse pass
                              {
                                  m_firstPassIndex++;

                                  float targetThroughput = _throughputTargets[m_firstPassIndex];
                                  m_intensitySettings.intensityN =
                                      (int)((m_intensitySettings.intensityD * targetThroughput) /
                                            (-targetThroughput + 1));

                                  if (m_firstPassIndex == _throughputTargets.size() - 1)
                                  {
                                      int bestIndex = findBestIntensitySoFar();
                                      sqrllog
                                          << EthOrange
                                          << "S3.0: First tuning pass complete, best ->"
                                          << m_shareTimes[bestIndex].first.to_string() << " with "
                                          << m_shareTimes[bestIndex].second / stage3_averageSeconds
                                          << "hs";

                                      vector<double> averages(m_shareTimes.size() - 1);
                                      for (int i = 0; i < m_shareTimes.size() - 1; i++)
                                      {
                                          averages[i] = (m_shareTimes[i].second +
                                                            m_shareTimes[i + 1].second) /
                                                        2;
                                      }
                                      for (int i = 0; i < m_shareTimes.size(); i++)
                                      {
                                          sqrllog << EthOrange << i << ","
                                                  << m_shareTimes[i].second;
                                      }
                                      // find best average to obtain the more fine tuning range
                                      int bestAvgIndex = 0;
                                      double bestAvg = averages[bestAvgIndex];
                                      for (int i = 1; i < averages.size(); i++)
                                      {
                                          if (averages[i] > averages[bestAvgIndex])
                                          {
                                              bestAvgIndex = i;
                                              bestAvg = averages[i];
                                          }
                                          sqrllog << EthOrange << "[" << i << "]avg=>"
                                                  << averages[i];
                                      }
                                      m_secondPassLowerN =
                                          m_shareTimes[bestAvgIndex].first.intensityN;
                                      m_secondPassUpperN =
                                          m_shareTimes[bestAvgIndex + 1].first.intensityN;

                                      uint8_t diff = m_secondPassUpperN - m_secondPassLowerN;
                                      int stepSize = diff / 5;
                                      if (stepSize < 0)
                                          stepSize = 1;
                                      m_secondPassStepSizeN = stepSize;

                                      sqrllog << EthOrange
                                              << "S3.1: Starting fine tuning (second pass) of N, "
                                                 "within the "
                                                 "range ["
                                              << (int)m_secondPassLowerN << "-"
                                              << (int)m_secondPassUpperN << "]";

                                      m_shareTimes.clear();  // clear for the second pass
                                      m_intensitySettings.intensityN = m_secondPassLowerN;
                                  }
                              }
                            else  // second - fine pass of N
                            {
                                if (m_intensitySettings.intensityN <= m_secondPassUpperN)
                                {
                                    m_intensitySettings.intensityN += m_secondPassStepSizeN;
                                }
                                else
                                {
                                    sqrllog << EthOrange << "S3.1: Best setting so far ->"
                                            << m_bestSettingsSoFar.first.to_string()
                                            << " with hashrate="
                                            << m_bestSettingsSoFar.second / stage3_averageSeconds;
                                    m_bestIntensityRangeFound = true;
                                    m_shareTimes.clear();
                                    m_intensitySettings.patience++;
                                    m_intensitySettings.intensityN = m_secondPassLowerN;
                                }
                            }
                        }
                        else  // Stage 3.2 -> increase patience, retest
                        {
                            if (m_intensitySettings.intensityN <= m_secondPassUpperN)
                            {
                                m_intensitySettings.intensityN += m_secondPassStepSizeN;
                            }
                            else
                            {
                                if (m_bestSettingsSoFar.first.patience ==
                                    m_intensitySettings.patience)
                                {  // we got new best with increased patience, keep increasing...
                                    m_intensitySettings.patience++;
                                    sqrllog << EthOrange << "S3.2: Best setting so far ->"
                                            << m_bestSettingsSoFar.first.to_string()
                                            << " with hashrate="
                                            << m_bestSettingsSoFar.second / stage3_averageSeconds;
                                }
                                else
                                {
                                    sqrllog << EthOrange
                                            << "Intensitivity tuning finished! Best settings="
                                            << m_bestSettingsSoFar.first.to_string()
                                            << " with hashrate="
                                            << m_bestSettingsSoFar.second / stage3_averageSeconds;

                                    m_intensitySettings = m_bestSettingsSoFar.first;
                                    m_intensityTuneFinished = true;
                                }
                            }
                        }
                        sqrllog << EthBlueBold << "Average hashrate during tuning period="
                                << (m_hashCounter / stage3_averageSeconds) / pow(10, 7) << "MHs";
                        m_lastTuneTime = std::chrono::steady_clock::now();
                        clearSolutionStats();
                    }
                }
            }
        
       
    }
    
}
int SQRLMiner::findBestIntensitySoFar()
{
    int bestIndex = 0;
    double bestTime = m_shareTimes[0].second;
    for (int i = 1; i < m_shareTimes.size(); i++)
    {
        double t = m_shareTimes[i].second;
        if (t > bestTime)
        {
            bestIndex = i;
            bestTime = t;
          
        }
    }
    return bestIndex;
}

void SQRLMiner::clearSolutionStats()
{
    _telemetry->miners.at(m_index).solutions.accepted = 0;
    _telemetry->miners.at(m_index).solutions.failed = 0;
    _telemetry->miners.at(m_index).solutions.low = 0;
    _telemetry->miners.at(m_index).solutions.rejected = 0;
    _telemetry->miners.at(m_index).solutions.wasted = 0;

    m_hashCounter = 0;
}
float SQRLMiner::getHardwareErrorRate()
{
    auto sol = getSolutions();
    int allSolutions = sol.accepted + sol.failed + sol.low;
    int failedSolutions = sol.failed;
    if (allSolutions == 0)
        return 0;

    return failedSolutions / (float)allSolutions;
}
SolutionAccountType SQRLMiner::getSolutions()
{
    return _telemetry->miners.at(m_index).solutions;
}
double SQRLMiner::getClock() {
  return setClock(-1);
}

double SQRLMiner::setClock(double targetClk) {
  uint32_t valueVCO;
  SQRLAXIRead(m_axi, &valueVCO, 0x8200);
  double mult = (double)((valueVCO>>8) &0xFF);
  double frac = 0;
  if ((valueVCO >> 16) & 0x2F) {
     frac = ((double)((valueVCO >> 16) & 0x3FF)) / 1000;
  }
  double gdiv = (valueVCO & 0xF);
  double vco = 200.0 * (mult+frac);
  vco /= gdiv;

  uint32_t valueClk0;
  SQRLAXIRead(m_axi, &valueClk0, 0x8208);
  double clk0div = (double)(valueClk0 & 0xF);
  double clk0FracDiv = ((double)((valueClk0 >> 8) & 0x3FF))/1000;
  clk0div += clk0FracDiv;

  double currentClk = vco / clk0div;

  // Changing?
  uint32_t nItems,rnItems;
  uint32_t daggenPwrState;
  if (targetClk != -1.0) {
    // Make sure we backup mining parameters - clock unlock can reset these
    SQRLAXIRead(m_axi, &nItems, 0x5040);
    SQRLAXIRead(m_axi, &rnItems, 0x5088);
    // Ensure DAGGEN is powered on
    SQRLAXIRead(m_axi, &daggenPwrState, 0xB000);   
    SQRLAXIWrite(m_axi, 0xFFFFFFFF, 0xB000, true);   
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
      SQRLAXIWrite(m_axi, newDiv, 0x8208, true);
      SQRLAXIWrite(m_axi, 0x7, 0x825c, true);
      SQRLAXIWrite(m_axi, 0x3, 0x825c, true);
      currentClk = vco/desiredDiv;
      sqrllog << "Setting CoreClk to " << (int)currentClk;
      m_lastClk = (int)currentClk;
    }
  } else if (targetClk < -1.0) {
    sqrllog << "Resetting CoreClk to Stock";
    // Reset to factory defaults
    SQRLAXIWrite(m_axi, 0x5, 0x825c, true);
    SQRLAXIWrite(m_axi, 0x1, 0x825c, true);
#ifdef _WIN32
    Sleep(10);
#else
    usleep(10000);
#endif
    SQRLAXIWrite(m_axi, 0xA, 0x8000, true);
  }
  if (targetClk != -1.0) {
    // Wait for locked
    uint32_t waitCnt=1000;
    while(waitCnt--) {
      uint32_t locked;
      SQRLAXIRead(m_axi, &locked, 0x8004);
      if (locked&1) break;
    }

    // Make sure we restore the mining parameters 
    SQRLAXIWrite(m_axi, nItems, 0x5040, true);
    SQRLAXIWrite(m_axi, rnItems, 0x5088, true);
    SQRLAXIWrite(m_axi, daggenPwrState, 0xB000, true);
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
  SQRLAXIRead(m_axi, &raw, 0x3400);
  (*tempC) = ((double)raw * 507.6 / 65536.0) - 279.43;
  (*fanprct) = getClock(); 
  SQRLAXIRead(m_axi, &raw, 0x3404);
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
    if (numDevices == 1)  // 127.0.0.1:2000-20XX
    {
        string s = _settings.hosts[0];
        if ((s.find("-") != std::string::npos) && (s.find(":") != std::string::npos) && (s.find(":") < s.find("-")))
        {
            vector<string> strs;
            boost::split(strs, s, boost::is_any_of(":"));

            string ip = strs[0];
            string portRange = strs[1];

            vector<string> ports;
            boost::split(ports, portRange, boost::is_any_of("-"));

            int startPort = std::stoi(ports[0]);
            int endPort = std::stoi(ports[1]);
            _settings.hosts.clear();

            for (int i = startPort; i <= endPort; i++)
            {
                string newIpPort = ip + ":" + std::to_string(i);
                _settings.hosts.push_back(newIpPort);
            }

            numDevices = getNumDevices(_settings);
        }
    }

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
