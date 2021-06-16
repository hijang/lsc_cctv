#pragma once
#ifndef __PLogger_H__
#define __PLogger_H__ 1
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cstdarg>
#include <ctime>
#include <sstream>
#include <cstring>
#include <cstdio>
#define LOG_LEVEL_OFF 0
#define LOG_LEVEL_FATAL 10
#define LOG_LEVEL_ERROR 20
#define LOG_LEVEL_INFO 40
#define LOG_LEVEL_TRACE 60
#define LOG_LEVEL_ALL 100
#define fatal(str, ...) writeLog(LOG_LEVEL_FATAL,__FUNCTION__, __LINE__, str)
#define error(str, ...) writeLog(LOG_LEVEL_ERROR,__FUNCTION__, __LINE__, str)
#define info(str, ...) writeLog(LOG_LEVEL_INFO,__FUNCTION__, __LINE__, str)
#define trace(str, ...) writeLog(LOG_LEVEL_TRACE,__FUNCTION__, __LINE__, str)
using namespace std;
class PLogger {
private:
    int logLevel;
    string m_FileName;
    string m_FileFormat=".log";
    int m_FileCount=0;
    string getTimestamp();
    string getLogFileName();
    int32_t fileSize(string filename);
    void splitFile();
public:
    PLogger();
    PLogger(int level);
    void writeLog(int level, const char* funcName, int line, const char* str);
};
static PLogger logg;
#endif