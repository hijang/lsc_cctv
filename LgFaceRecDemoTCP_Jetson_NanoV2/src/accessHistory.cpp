#include "accessHistory.h"
#include "logger.h"

#define MAX_CONTINUOUS_TIME 10

accessHistory::accessHistory()
{

}

void accessHistory::insertToMySet(string str)
{
    m_myset.insert(str);
}

void accessHistory::printLog(int cropsize)
{
    int cropFaceSize = cropsize; //Number of faces recognized in a frame
    int knownFaceSize = m_myset.size(); //Number of faces recognized in a frame

    if (cropFaceSize > knownFaceSize)
    {
        logg.fatal("there is (%d) new person \n", cropFaceSize - knownFaceSize);
    }

    if (knownFaceSize > 0)
    {
        if (m_oldmap.empty())
        {
            for (auto it = m_myset.begin(); it != m_myset.end(); it++)
            {
                m_oldmap.insert(pair<string, int>((*it).c_str(), 1));
                logg.trace("%s is in\n", (*it).c_str());
            }
            return;
        }

        for (auto it = m_oldmap.begin(); it != m_oldmap.end(); it++)
        {
            if (m_myset.count(it->first))
            {
                if (it->second < MAX_CONTINUOUS_TIME)
                    it->second += 1;
            }
            else
            {
                it->second -= 1;
            }
        }

        for (auto it = m_myset.begin(); it != m_myset.end(); it++)
        {
            if (m_oldmap.find(*it) == m_oldmap.end())  //This is new face
            {
                m_oldmap.insert(pair<string, int>((*it).c_str(), 1));
                logg.trace("%s is in\n", (*it).c_str());
            }
        }
    }
    else
    {
        if (!m_oldmap.empty()) //If set is not empty, you need to subtract
        {
            for (auto it = m_oldmap.begin(); it != m_oldmap.end(); it++)
            {
                it->second -= 1;
            }
        }
    }

    for (auto it = m_oldmap.begin(); it != m_oldmap.end(); it++) //print log
    {
        if (0 == it->second)
        {
            logg.trace("%s is out\n", it->first.c_str());
        }
        else if (MAX_CONTINUOUS_TIME == it->second)
        {
            logg.trace("%s stay\n", it->first.c_str());
            it->second -= 5;
        }
        else
        {
            continue;
        }
    }

    for (auto it = m_oldmap.begin(); it != m_oldmap.end(); ) //clean history map
    {
        if (0 == it->second)
        {
            it = m_oldmap.erase(it);
        }
        else
        {
            it++;
        }
    }
    m_myset.clear();
}