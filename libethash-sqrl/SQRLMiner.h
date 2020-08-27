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

#include <functional>


#define format2decimal(x) boost::str(boost::format(" %0.2f") % x)

namespace dev
{
namespace eth
{
struct IntensitySettings
{
    unsigned int patience;
    unsigned int intensityN;
    unsigned int intensityD;

    IntensitySettings()
    {
        patience = 0;
        intensityN = 0;
        intensityD = 0;
    }
    string to_string()
    {
        return "P=" + std::to_string(patience) + " N=" + std::to_string(intensityN) + " D=" + std::to_string(intensityD);
    }
};
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

protected:
    bool initDevice() override;
    bool initEpoch_internal() override;
    void kick_miner() override;

   

private:
    atomic<bool> m_new_work = {false};
    atomic<bool> m_dagging = {false};
    void workLoop() override;
    SQSettings m_settings;
	double VoltageTbl[256] = { 0.0 };
	void InitVoltageTbl(void);
	uint8_t FindClosestVIDToVoltage(double ReqVoltage);
	double LookupVID(uint8_t VID);
    double getClock();
    double setClock(double targetClk);

    atomic<double> m_lastClk = {0};
    SQRLAXIRef m_axi = NULL;
    std::mutex axiMutex;
    double m_hashCounter = 0;
    double m_avgValues[4]; //1min avg hash, 10min avg hash, 60min avg hash, error rate
    vector<double> m_10minHashAvg;
    vector<double> m_60minHashAvg;

    // auto tune
    typedef std::chrono::steady_clock::time_point timePoint;
    void autoTune(uint64_t newTcks);
    double average(std::vector<double> const& v);
    void clearSolutionStats();
    int findBestIntensitySoFar();
    float getHardwareErrorRate();

    SolutionAccountType getSolutions();
    atomic<timePoint> m_lastTuneTime = {std::chrono::steady_clock::now()};
    atomic<timePoint> m_avgHashTimer = {std::chrono::steady_clock::now()};
    atomic<bool> m_maxFreqReached = {false};
    atomic<bool> m_stableFreqFound = {false};
    std::vector<int> _freqSteps = {300, 309, 320, 331, 342, 355, 369, 384, 400, 417, 436, 457, 480, 505, 533, 564, 600};

    TelemetryType* _telemetry;
    IntensitySettings m_intensitySettings;
    atomic<bool> m_intensityTuning = {false};
    vector<pair<IntensitySettings, double>> m_shareTimes; // how many target checks in set time
    std::vector<float> _throughputTargets = {0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.92};
    uint8_t m_firstPassIndex = 0;
    uint8_t m_secondPassLowerN = 0;
    uint8_t m_secondPassUpperN = 0;
    double m_tuneHashCounter = {0};
    uint8_t m_secondPassStepSizeN = 0;
    pair<IntensitySettings, double> m_bestSettingsSoFar;
    bool m_bestIntensityRangeFound = false;
    bool m_intensityTuneFinished = false;


};


}  // namespace eth
}  // namespace dev
