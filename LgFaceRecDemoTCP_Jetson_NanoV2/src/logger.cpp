#include "logger.h"
#include "time.h"
#include <string>

#define MAX_LENGTH 10

PLogger::PLogger()
{
    this->logLevel = LOG_LEVEL_ERROR;
}
PLogger::PLogger(int level)
{
    this->logLevel = level;
}
string PLogger::getTimestamp()
{
    time_t rawtime = time(NULL);
    struct tm* tm_recent = localtime(&rawtime);

    ostringstream oss;
    switch (tm_recent->tm_mon)
    {
    case(0): result = "Jan"; break;
    case(1): result = "Feb"; break;
    case(2): result = "Mar"; break;
    case(3): result = "Apr"; break;
    case(4): result = "May"; break;
    case(5): result = "Jun"; break;
    case(6): result = "Jul"; break;
    case(7): result = "Aug"; break;
    case(8): result = "Sep"; break;
    case(9): result = "Oct"; break;
    case(10): result = "Nov"; break;
    case(11): result = "Dec"; break;
    }
    oss.clear();
    oss << "/" << setfill('0') << setw(2) << tm_recent->tm_mday << "/" << tm_recent->tm_year + 1900;
    oss << " " << setfill('0') << setw(2) << tm_recent->tm_hour;
    oss << ":" << setfill('0') << setw(2) << tm_recent->tm_min;
    oss << ":" << setfill('0') << setw(2) << tm_recent->tm_sec << '\0';

    return oss.str();
}

string PLogger::getLogFileName()
{
    string result;

    time_t rawtime = time(NULL);
    struct tm* date = localtime(&rawtime);

    ostringstream oss;
    oss << date->tm_year + 1900 << setfill('0') << setw(2) << date->tm_mon+1 << setfill('0') << setw(2) << date->tm_mday<< ".log" << '\0';
    result = result + oss.str();
    return result;
}

void PLogger::writeLog(int lv, const char* funcName, int line, const char* str, ...)
{
    FILE* fp = NULL;
    fp = fopen(getLogFileName().c_str(), "a"); // fopen_s�� ���� �� 0�̰�, ���н� ���� �ڵ� ��ȯ������ �ѱ�
    //fopen_s(&fp, getLogFileName().c_str(), "a");
    if (NULL == fp) 
    {
        puts("Error code on fail to open file");
        return;
    }
    
    char* result = NULL;
    char level[MAX_LENGTH];
    level[0] = '\0';
    switch (lv)
    {
    case(LOG_LEVEL_FATAL): strncpy(level, "[FATAL]", MAX_LENGTH-1); break;
    case(LOG_LEVEL_ERROR): strncpy(level, "[ERROR]", MAX_LENGTH-1); break;
    case(LOG_LEVEL_INFO): strncpy(level, "[INFO] ", MAX_LENGTH-1); break;
    case(LOG_LEVEL_TRACE): strncpy(level, "[TRACE]", MAX_LENGTH-1); break;
    }

    string timeStamp = getTimestamp();
    int result_len = strlen(level) + timeStamp.size() + strlen(funcName) + to_string(line).size() + strlen(str) + 10;
    result = (char*)malloc(sizeof(char) * result_len);

    if (result == NULL)
    {
        puts("Error code on fail to open file");
        return;        
    }
    else
    {
        int res = snprintf(result, result_len,"%s %s [%s:%d] : %s\n", level, timeStamp.c_str(), funcName, line, str);
        va_list args;
        va_start(args, str);
        vfprintf(fp, result, args);
        fflush(fp);
        va_end(args);
        va_start(args, str);
        if (this->logLevel >= lv)
        {
            vprintf(result, args);
        }
        va_end(args);

        free(result);
    }

    if (fp != NULL)
    {
        fclose(fp);
    }

    return;
}