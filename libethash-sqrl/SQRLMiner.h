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

//#pragma optimize("", off)
namespace dev
{
namespace eth
{
class SQRLMiner : public Miner
{
public:
    SQRLMiner(unsigned _index, SQSettings _settings, DeviceDescriptor& _device, TelemetryType* telemetry);
    ~SQRLMiner() override;

    static unsigned getNumDevices(SQSettings _settings);
    static void enumDevices(
        std::map<string, DeviceDescriptor>& _DevicesCollection, SQSettings _settings);

    void search(const dev::eth::WorkPackage& w);
    void getTelemetry(unsigned int* tempC, unsigned int* fanprct, unsigned int* powerW) override;

protected:
    bool initDevice() override;
    bool initEpoch_internal() override;
    void kick_miner() override;

private:
    atomic<bool> m_new_work = {false};
    atomic<bool> m_dagging = {false};
    void workLoop() override;
    SQSettings m_settings;
    

    double getClock();
    double setClock(double targetClk);

    atomic<double> m_lastClk = {0};
    SQRLAXIRef m_axi = NULL;
    std::mutex axiMutex;

    // auto tune
    typedef std::chrono::steady_clock::time_point timePoint;
    void autoTune();
    void clearSolutionStats();
    SolutionAccountType getSolutions();
    atomic<timePoint> m_lastTuneTime = {std::chrono::steady_clock::now()};
    atomic<bool> m_maxFreqReached = {false};
    atomic<bool> m_stableFreqFound = {false};
    std::vector<int> _freqSteps = {300, 309, 320, 331, 342, 355, 369, 384, 400, 417, 436, 457, 480, 505, 533, 564, 600};

    TelemetryType* _telemetry;


};


}  // namespace eth
}  // namespace dev
