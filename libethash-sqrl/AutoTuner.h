#pragma once
#include "SQRLMiner.h"
#include <fstream>

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
    bool isSet() { return !(patience == 0 || intensityD == 0 || intensityN == 0); }
    string to_string()
    {
        return "P=" + std::to_string(patience) + " N=" + std::to_string(intensityN) +
               " D=" + std::to_string(intensityD);
    }
};
class SQRLMiner;

class AutoTuner
{
   private:
    SQRLMiner* _minerInstance = NULL;
    TelemetryType* _telemetry = NULL;
    SQSettings* _settings = NULL;
    unsigned _minerIndex = 0;
    vector<unsigned> _freqSteps = {0, 100, 200, 246, 252, 259, 266, 274, 282, 290, 300, 309, 320, 331,
        342, 355, 369, 384, 400, 417, 436, 457, 480, 505, 533, 564, 600};

    vector<double> _throughputTargets = {0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.92};

    typedef std::chrono::steady_clock::time_point timePoint;

    double _tuneHashCounter = 0;
    timePoint _lastTuneTime = std::chrono::steady_clock::now();
    timePoint _tuneTempCheckTimer = std::chrono::steady_clock::now();
    
    uint8_t _tuningStage = 0;
    bool _stableFreqFound = false;
    bool _maxFreqReached = false;
    double _lastClock = 0;
    bool _intensityTuneFinished = false;
    bool _intensityTuning = false;
    bool _bestIntensityRangeFound = false;

    uint8_t _firstPassIndex = 0;
    uint8_t _secondPassLowerN = 0;
    uint8_t _secondPassUpperN = 0;
    uint8_t _secondPassStepSizeN = 0;

    IntensitySettings _intensitySettings;
    pair<IntensitySettings, double> _bestSettingsSoFar;
    vector<pair<IntensitySettings, double>> _shareTimes;  // how many target checks in set time
    

    void tuneStage1(uint64_t elapsedSeconds, unsigned currentStepIndex, vector<unsigned>::iterator it, float mhs);
    bool tuneStage2(unsigned currentStepIndex);
    bool tuneStage3(uint64_t elapsedSeconds);
    int findBestIntensitySoFar();
    void clearSolutionStats();
    bool saveTune();
    bool temperatureSafetyCheck(unsigned currentStepIndex);
    
   

public:
    AutoTuner(SQRLMiner* minerInstance, TelemetryType* telemetry);
    ~AutoTuner(){};
    

    void startTune(double clk);
    void tune(uint64_t newTcks);
    bool readSavedTunes(string fileName, string settingID);
    float getHardwareErrorRate();
    uint8_t getTuningStage() { return _tuningStage; }
    IntensitySettings getIntensitySettings() { return _intensitySettings; }
};


}  // namespace eth
}  // namespace dev
