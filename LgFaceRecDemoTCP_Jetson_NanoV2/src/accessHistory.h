#pragma once
#ifndef __ACCESSHistory_H__
#define __ACCESSHistory_H__ 1
#include <iostream>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <numeric>

using namespace std;

class accessHistory {
private:
    std::unordered_set<std::string> m_myset;
    std::unordered_map<std::string, int> m_oldmap;
public:
    accessHistory();
    //std::unordered_set<std::string>* getMySet();
    void insertToMySet(std::string);
    void printLog(int cropsize);
};

static accessHistory record;
#endif
