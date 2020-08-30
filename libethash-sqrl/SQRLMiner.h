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

#pragma once

#include <libdevcore/Worker.h>
#include <libethcore/EthashAux.h>
#include <libethcore/Miner.h>
#include "SQRLAXI.h"
#include "AutoTuner.h"
#include <functional>

//#pragma optimize("", off)

#define format2decimal(x) boost::str(boost::format(" %0.2f") % x)

namespace dev
{
namespace eth
{
struct SQRLChannel : public LogChannel
{
    static const char* name() { return EthOrange "sq"; }
    static const int verbosity = 2;
};
#define sqrllog clog(SQRLChannel)

class AutoTuner;

class SQRLMiner : public Miner
{

public:
    SQRLMiner(unsigned _index, SQSettings _settings, DeviceDescriptor& _device, TelemetryType* telemetry);
    ~SQRLMiner() override;

    static unsigned getNumDevices(SQSettings _settings);
    static void enumDevices(std::map<string, DeviceDescriptor>& _DevicesCollection, SQSettings _settings);

    void search(const dev::eth::WorkPackage& w);
    void processHashrateAverages(uint64_t newTcks);

    void getTelemetry(unsigned int *tempC, unsigned int *fanprct, unsigned int *powerW) override;

    SQSettings* getSQsettigns() { return &m_settings; }
    unsigned getMinerIndex() { return m_index; }

    double getClock();
    double setClock(double targetClk);
    string getSettingsID() { return m_settingID; }
    uint8_t* getFPGAtemps() { return m_FPGAtemps; }
    void setLastClock(double lastClk) { m_lastClk = lastClk; }

protected:
    bool initDevice() override;

    void setVoltage(unsigned fkVCCINT = 0, unsigned jcVCCINT = 0);

    bool initEpoch_internal() override;
    void kick_miner() override;

   

private:
    string m_settingID = "";  // DNA_bitstream_V used for saving tuning config

    atomic<bool> m_new_work = {false};
    atomic<bool> m_dagging = {false};
   
    SQRLAXIRef m_axi = NULL;
    std::mutex axiMutex;
    SQSettings m_settings;
    AutoTuner* m_tuner;

    void workLoop() override;
  
    //Voltages
	double VoltageTbl[256] = { 0.0 };

	void InitVoltageTbl(void);
	uint8_t FindClosestVIDToVoltage(double ReqVoltage);
	double LookupVID(uint8_t VID);

    //Clock
    atomic<double> m_lastClk = {0};

    //Averages
    double m_hashCounter = 0;
    double m_avgValues[4]; //1min avg hash, 10min avg hash, 60min avg hash, error rate
    vector<double> m_10minHashAvg;
    vector<double> m_60minHashAvg;
    uint8_t m_FPGAtemps[3];//core,HBM-left,HBM-right;
   
    double average(std::vector<double> const& v);
    atomic<std::chrono::steady_clock::time_point> m_avgHashTimer = {
        std::chrono::steady_clock::now()};

};


}  // namespace eth
}  // namespace dev
