#include "AutoTuner.h"

using namespace std;
using namespace dev;
using namespace eth;


#define sqrllog clog(SQRLChannel)

AutoTuner::AutoTuner(SQRLMiner* minerInstance, TelemetryType* telemetry)
{
    _minerInstance = minerInstance;
    _telemetry = telemetry;
    _settings = _minerInstance->getSQsettigns();
    _minerIndex = _minerInstance->getMinerIndex();
}

void AutoTuner::startTune(double clk) {
    _lastTuneTime = std::chrono::steady_clock::now();
    _lastClock = clk;
}

void AutoTuner::tune(uint64_t newTcks)
{
    auto it = std::find(_freqSteps.begin(), _freqSteps.end(), _lastClock);
    auto currentStepIndex = std::distance(_freqSteps.begin(), it);
    if (!temperatureSafetyCheck(currentStepIndex))
        return;


    // if FPGA is excluded from tuning - don't bother
    if (std::find(_settings->tuneExclude.begin(), _settings->tuneExclude.end(), _minerIndex) !=
        _settings->tuneExclude.end())
        return;

    _tuneHashCounter += newTcks;

    float hash = _minerInstance->RetrieveHashRate();
    float mhs = hash / pow(10, 6);
    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - (timePoint)_lastTuneTime)
                              .count();

    bool tuningFinished = false;

    if (_settings->autoTune >= 1 && _settings->autoTune <= 3)  // Stage 1: Do a quick tune to get max frequency
        tuneStage1(elapsedSeconds, currentStepIndex, it, mhs);

    // Autotune 4 runs stage 2 and 3 only
    if ((_settings->autoTune >= 2 && _settings->autoTune <= 3) || _settings->autoTune == 4)  // Stage 2: Check for long term stability and error rate (removes
                                   // marginally stable)
    {
        if (tuneStage2(currentStepIndex))
            if (_settings->autoTune == 2)
                tuningFinished = true;
    }

    if (_settings->autoTune >= 4)
    {
      _maxFreqReached = true;
      if (_settings->autoTune >= 5) {
        _stableFreqFound = true;  
      }
    }

    // Autotune 5 runs only this stage
    if (_settings->autoTune >= 3)  // Stage 3: Tune N and P for given D.
    {
        if (tuneStage3(elapsedSeconds))
            if (_settings->autoTune == 3 || _settings->autoTune == 5)
                tuningFinished = true;
    }


    if (tuningFinished)  // save the tune for re-use
    {
        for (int i = 0; i < 3; i++)
        {
            if (!saveTune())
#ifdef _WIN32
                Sleep(10);  // in case file busy, try couple times
#else
                usleep(10000);
#endif
            else
                break;
        }
        _tuningStage = 0;
    }
}
void AutoTuner::tuneStage1(
    uint64_t elapsedSeconds, unsigned currentStepIndex, vector<unsigned>::iterator it, float mhs)
{
    if (_stableFreqFound)  // nothing to do...
        return;

    // Stage 1:
    uint64_t stage1_averageSeconds = 60;
    float throughput =
        (float)_settings->intensityN / (_settings->intensityN + _settings->intensityD);
    float stabilityThreshold = ((_lastClock / 8) * throughput) * _settings->tuneStabilityThreshold;


    if (elapsedSeconds > stage1_averageSeconds)
    {
        if (it == _freqSteps.end())
        {
            sqrllog << EthOrange << "S1: Could not find starting index, stopping...";
            return;
        }

        if (mhs > stabilityThreshold)  // assume above threshold mhs -> stable, can try higher clock
        {
            if (!_maxFreqReached)
            {
                if (currentStepIndex != _freqSteps.size() - 1 &&
                    _freqSteps[currentStepIndex] != _settings->tuneMaxClk)  // not getting out of
                                                                            // bounds
                {
                    int nextClock = _freqSteps[currentStepIndex + 1] + 1;  //+1 for precision issues
                    sqrllog << EthOrange << "S1: Stable at " << _lastClock << "MHz, trying "
                            << nextClock - 1 << "...";
                    _minerInstance->setClock(nextClock);
                    _lastClock = nextClock - 1;
                }
                else
                {
                    sqrllog << EthOrange << "Clocking out of bounds, max frequency reached!";
                    _maxFreqReached = true;
                }
            }
        }
        else  // Unstable, downclock...
        {
            _maxFreqReached = true;
            if (currentStepIndex > 0)
            {
                int nextClock = _freqSteps[currentStepIndex - 1] + 1;  //+1 for precision issues
                sqrllog << EthOrange << "S1: Unstable at " << _lastClock << "MHz, downclocking to "
                        << nextClock - 1 << "...";
                _minerInstance->setClock(nextClock);
                _lastClock = nextClock - 1;

                clearSolutionStats();
            }
            else
                sqrllog << EthOrange << "S1: Clocking out of bounds, min frequency reached!";
        }
        _tuningStage = 1;

        _lastTuneTime = std::chrono::steady_clock::now();
    }
}
bool AutoTuner::tuneStage2(unsigned currentStepIndex)
{
    // Stage 2:
    float errorRateThreshold = 0.03;  // 3%
    int tuningShareCount = _settings->tuneTime;  // how many low shares to check to derive average from

    if (_maxFreqReached && !_stableFreqFound)
    {
        // calculate error rate
        auto solutions = _telemetry->miners.at(_minerIndex).solutions;

        if (solutions.low > 0 && (solutions.low + solutions.failed) % tuningShareCount == 0)
        {
            float errorRate = getHardwareErrorRate();

            if (errorRate > errorRateThreshold)
            {
                sqrllog << EthOrange << "S2: Error rate of " << errorRate * 100
                        << "% above threshold (" << errorRateThreshold * 100
                        << "%), downclocking...";
                int nextClock = _freqSteps[currentStepIndex - 1] + 1;  //+1 for precision issues
                _minerInstance->setClock(nextClock);
                _lastClock = nextClock - 1;

                clearSolutionStats();
            }
            else
            {
                sqrllog << EthOrange << "S2: Stable long term frequency found at " << _lastClock
                        << "MHz";              
                _stableFreqFound = true;
                return true;
            }
        }
        _tuningStage = 2;
    }
    return false;
}
/*
1. Move frequency up until 0 target checks or invalids, then back off one tick (inc 0.125 on
divider)
2. Start with ~60%, increase intensity or binary search until you find the local maxima. Do this
with patience 1
3. Set patience up by 1, search +/- 2/3 inn values for a new local maxima
4. Repeat until patience makes it worse
*/
bool AutoTuner::tuneStage3(uint64_t elapsedSeconds)
{
    if (_intensityTuneFinished)  // nothing to do, finished...
        return false;

    // Stage 3:
    unsigned stage3_averageSeconds = _settings->tuneTime;

    if (_stableFreqFound)
    {
        _tuningStage = 3;
        if (!_intensityTuning)  // init
        {
            float targetThroughput = _throughputTargets[_firstPassIndex];
            _intensitySettings.patience = _settings->patience;  // start with user defined
            _intensitySettings.intensityD = _settings->intensityD;
            _intensitySettings.intensityN =
                (int)((_intensitySettings.intensityD * targetThroughput) /
                      (-targetThroughput + 1));  // derive inital N from 60% throughput.

            clearSolutionStats();
            _intensityTuning = true;
            sqrllog << EthOrange << "S3: Intensity tuning started... init settings ->"
                    << _intensitySettings.to_string();

            _lastTuneTime = std::chrono::steady_clock::now();
        }
        else
        {
            if (elapsedSeconds > stage3_averageSeconds)
            {
                float errorRate = getHardwareErrorRate();

                float throughput =
                    (float)_intensitySettings.intensityN /
                                   (_intensitySettings.intensityN + _intensitySettings.intensityD);

                pair<IntensitySettings, double> p;

                double adjustedHash = (_tuneHashCounter / elapsedSeconds) * (1 - errorRate);
                p = std::make_pair(_intensitySettings, adjustedHash);  // penalize for
                                                                        // producing errors

                if (_bestSettingsSoFar.second < adjustedHash)
                    _bestSettingsSoFar = p;

                _shareTimes.push_back(p);
                sqrllog << EthOrange << "S3: [" << _intensitySettings.to_string()
                        << "] errorRate=" << errorRate * 100 << "% Hashrate=" << adjustedHash
                        << " throughput=" << throughput * 100 << "%";


                if (!_bestIntensityRangeFound)  // Stage 3.1: Tune intensity, find best range
                {
                    if (_secondPassLowerN == 0 && _secondPassUpperN == 0)  // still first
                                                                             // coarse pass
                    {
                        _firstPassIndex++;

                       if (_firstPassIndex < _throughputTargets.size())
                       {
                           float targetThroughput = _throughputTargets[_firstPassIndex];
                           _intensitySettings.intensityN =
                               (int)((_intensitySettings.intensityD * targetThroughput) /
                                     (-targetThroughput + 1)); 

                           if (_intensitySettings.intensityN > 255)
                               _intensitySettings.intensityN = 255; // capped at uint8_t
                       }
                       else
                       {
                           int bestIndex = findBestIntensitySoFar();
                           sqrllog << EthOrange << "S3.0: First tuning pass complete, best ->"
                                   << _shareTimes[bestIndex].first.to_string() << " with "
                                   << _shareTimes[bestIndex].second / stage3_averageSeconds << "hs";

                           vector<double> averages(_shareTimes.size() - 1);
                           for (unsigned i = 0; i < _shareTimes.size() - 1; i++)
                           {
                               averages[i] =
                                   (_shareTimes[i].second + _shareTimes[i + 1].second) / 2;
                           }
                           _tuneLog <<endl<< "_shareTimes [3.0],";
                           for (unsigned i = 0; i < _shareTimes.size(); i++)
                           {
                               sqrllog << EthOrange << i << "," << _shareTimes[i].second;
                               _tuneLog << "[" << _shareTimes[i].first.to_string() << ";"
                                        << _shareTimes[i].second << "],";
                           }
                           // find best average to obtain the more fine tuning range
                           int bestAvgIndex = 0;
                           _tuneLog << endl<<"Averages [3.0]," << averages[0] <<",";
                           for (unsigned i = 1; i < averages.size(); i++)
                           {
                               if (averages[i] > averages[bestAvgIndex])
                               {
                                   bestAvgIndex = i;
                               }
                               sqrllog << EthOrange << "[" << i << "]avg=>" << averages[i];
                               _tuneLog << averages[i] << ",";
                           }
                           _secondPassLowerN = _shareTimes[bestAvgIndex].first.intensityN;
                           _secondPassUpperN = _shareTimes[bestAvgIndex + 1].first.intensityN;

                           uint8_t diff = _secondPassUpperN - _secondPassLowerN;
                           int stepSize = diff / 5;
                           if (stepSize <= 0)
                               stepSize = 1;
                           _secondPassStepSizeN = stepSize;

                           sqrllog << EthOrange
                                   << "S3.1: Starting fine tuning (second pass) of N, "
                                      "within the "
                                      "range ["
                                   << (int)_secondPassLowerN << "-" << (int)_secondPassUpperN
                                   << "]";
                           _tuneLog << endl<< "Tuning range [3.0]," << (int)_secondPassLowerN << ","
                                    << (int)_secondPassUpperN;
                           _shareTimes.clear();  // clear for the second pass
                           _intensitySettings.intensityN = _secondPassLowerN;
                       }
                    }
                    else  // second - fine pass of N
                    {
                        if (_intensitySettings.intensityN <= _secondPassUpperN)
                        {
                            _intensitySettings.intensityN += _secondPassStepSizeN;
                        }
                        else
                        {
                            sqrllog << EthOrange << "S3.1: Best setting so far ->"
                                    << _bestSettingsSoFar.first.to_string()
                                    << " with hashrate=" << _bestSettingsSoFar.second;

                            _tuneLog << endl << "_shareTimes [3.1],";
                            for (unsigned i = 0; i < _shareTimes.size(); i++)
                            {
                                _tuneLog << "["<<_shareTimes[i].first.to_string()<<";"<< _shareTimes[i].second << "],";
                            }
                            _bestIntensityRangeFound = true;
                            _shareTimes.clear();
                            _intensitySettings.patience++;
                            _intensitySettings.intensityN = _secondPassLowerN;
                        }
                    }
                }
                else  // Stage 3.2 -> increase patience, retest
                {
                    if (_intensitySettings.intensityN <= _secondPassUpperN)
                    {
                        _intensitySettings.intensityN += _secondPassStepSizeN;
                    }
                    else
                    {
                        if (_bestSettingsSoFar.first.patience == _intensitySettings.patience)
                        {  // we got new best with increased patience, keep increasing...
                            _intensitySettings.patience++;
                            sqrllog << EthOrange << "S3.2: Best setting so far ->"
                                    << _bestSettingsSoFar.first.to_string()
                                    << " with hashrate=" << _bestSettingsSoFar.second;

                            _shareTimes.clear();
                            _tuneLog << endl << "_shareTimes [3.2],";
                            for (unsigned i = 0; i < _shareTimes.size(); i++)
                            {
                                _tuneLog << "[" << _shareTimes[i].first.to_string() << ";"
                                         << _shareTimes[i].second << "],";
                            }
                        }
                        else
                        {
                            _tuneLog << endl
                                     << "best [3.2], [" << _bestSettingsSoFar.first.to_string()
                                     << ";" << _bestSettingsSoFar.second<<"]";
                            _intensitySettings = _bestSettingsSoFar.first;
                            _intensityTuneFinished = true;
                            return true;
                        }
                    }
                }
                sqrllog << EthBlueBold << "Average hashrate during tuning period="
                        << (_tuneHashCounter / stage3_averageSeconds) / pow(10, 6) << "MHs";
                _lastTuneTime = std::chrono::steady_clock::now();
                clearSolutionStats();
            }
        }
    }
    return false;
}

int AutoTuner::findBestIntensitySoFar()
{
    int bestIndex = 0;
    double bestTime = _shareTimes[0].second;
    for (unsigned i = 1; i < _shareTimes.size(); i++)
    {
        double t = _shareTimes[i].second;
        if (t > bestTime)
        {
            bestIndex = i;
            bestTime = t;
        }
    }
    return bestIndex;
}

void AutoTuner::clearSolutionStats()
{
    _telemetry->miners.at(_minerIndex).solutions.accepted = 0;
    _telemetry->miners.at(_minerIndex).solutions.failed = 0;
    _telemetry->miners.at(_minerIndex).solutions.low = 0;
    _telemetry->miners.at(_minerIndex).solutions.rejected = 0;
    _telemetry->miners.at(_minerIndex).solutions.wasted = 0;

    _tuneHashCounter = 0;
}

bool AutoTuner::readSavedTunes(string fileName, string settingID)
{
    // if FPGA is excluded from tuning - don't bother
    if (std::find(_settings->tuneExclude.begin(), _settings->tuneExclude.end(), _minerIndex) !=
        _settings->tuneExclude.end())
        return false;

    try
    {
        std::ifstream myfile(fileName);
        std::string line;
        bool tuneFound = false;
        while (std::getline(myfile, line))
        {
            std::vector<std::string> words;
            boost::split(words, line, boost::is_any_of(","), boost::token_compress_on);
            if (words.size() > 0)
            {
                if (words[0] == settingID)
                {
                    sqrllog << "Found a previous tune!";
                    _lastClock = stoi(words[1]);
                    _minerInstance->setLastClock(_lastClock+1);//for precision issues
                    _settings->patience = stoi(words[2]);
                    _settings->intensityN = stoi(words[3]);
                    _settings->intensityD = stoi(words[4]);
                    tuneFound = true;
                }
            }
        }
        if (tuneFound)
            return true;
    }
    catch (const exception& e)
    {
        sqrllog << EthRed << "Failed to parse tune file! ";
        sqrllog << EthRed << e.what();
    }
    return false;
}

bool AutoTuner::saveTune()
{
    ofstream ofs;
    ofs.open("tune.txt", std::ios_base::app);  // append instead of overwrite
    bool isOK = false;
    if (ofs.is_open())
    {
        sqrllog << EthOrange << "Tune finished, saving tune.txt!";
        ofs << _minerInstance->getSettingsID() << "," << _lastClock << ","
            << _bestSettingsSoFar.first.patience << "," << _bestSettingsSoFar.first.intensityN
            << "," << _bestSettingsSoFar.first.intensityD << endl;
        ofs.close();
        isOK = true;
    }
    else
    {
        sqrllog << EthRed << "Could not write tune file!";
        isOK = false;
    }
    if (isOK)
    {
        ofs.open("tuneLog.txt", std::ios_base::app);  // append instead of overwrite
        if (ofs.is_open())
        {
            ofs << _minerInstance->getSettingsID() << endl << _tuneLog.str() << endl;
            ofs.close();
            return true;
        }
        else
        {
            sqrllog << EthRed << "Could not write tune log!";
            return false;
        }
    }
    return false;
}
bool AutoTuner::temperatureSafetyCheck(unsigned currentStepIndex)
{
    int maxCore = _settings->tuneMaxCoreTemp;
    int maxHBM = _settings->tuneMaxHBMtemp;

    auto elapsedTempCheckSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - (timePoint)_tuneTempCheckTimer)
                                       .count();

    if (elapsedTempCheckSeconds > 10)  // check every 10 sec
    {
        if (_minerInstance->getClock() < 100)
        {
            sqrllog << EthRed << "FPGA appears to have crashed!";
            return false;
        }
        uint8_t* FPGAtemps = _minerInstance->getFPGAtemps();
        int tempCore = FPGAtemps[0];
        int tempLeft = FPGAtemps[1];
        int tempRight = FPGAtemps[2];

        if (tempCore >= maxCore || tempLeft >= maxHBM || tempRight >= maxHBM)
        {
            if (tempCore >= maxCore)
                sqrllog << EthRed << "Core temperature reaching max set temp of " << maxCore
                        << "C. Downclocking!";

            if (tempLeft >= maxHBM || tempRight >= maxHBM)
                sqrllog << EthRed << "HBM temperature reaching max set temp of " << maxHBM
                        << "C. Downclocking!";

            if (currentStepIndex > 0)
            {
                int nextClock = _freqSteps[currentStepIndex - 1] + 1;  //+1 for precision issues
                _minerInstance->setClock(nextClock);
                _lastClock = nextClock - 1;
            }
            else
            {
                sqrllog << EthRed << "Cannot clock any lower!";
                return false;
            }

            // Try and re-tune at lower clock and hope temps stay low
            _maxFreqReached = true;
            _stableFreqFound = false;
            _intensityTuning = false;
            _bestIntensityRangeFound = false;
            _intensityTuneFinished = false;
            clearSolutionStats();
            _tuningStage = 0;
        }

        _tuneTempCheckTimer = std::chrono::steady_clock::now();
    }
    return true;
}
float AutoTuner::getHardwareErrorRate()
{
    auto sol = _telemetry->miners.at(_minerIndex).solutions;
    int allSolutions = sol.accepted + sol.failed + sol.low;
    int failedSolutions = sol.failed;
    if (allSolutions == 0)
        return 0;

    return failedSolutions / (float)allSolutions;
}
