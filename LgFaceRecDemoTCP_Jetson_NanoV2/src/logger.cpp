#include "logger.h"
#include "time.h"
#include <string>
#include <sys/stat.h>

#define MAX_LENGTH 10
#define MAX_FILE_SIZE 100000

PLogger::PLogger()
{
    this->logLevel = LOG_LEVEL_ERROR;
    this->m_FileName = getLogFileName();
}
PLogger::PLogger(int level)
{
    this->logLevel = level;
    this->m_FileName = getLogFileName();
}
string PLogger::getTimestamp()
{
    time_t rawtime = time(NULL);
    struct tm* tm_recent = localtime(&rawtime);

    ostringstream oss;
    switch (tm_recent->tm_mon)
    {
    case(0): oss << "Jan"; break;
    case(1): oss <<  "Feb"; break;
    case(2): oss << "Mar"; break;
    case(3): oss << "Apr"; break;
    case(4): oss << "May"; break;
    case(5): oss << "Jun"; break;
    case(6): oss << "Jul"; break;
    case(7): oss << "Aug"; break;
    case(8): oss << "Sep"; break;
    case(9): oss << "Oct"; break;
    case(10): oss << "Nov"; break;
    case(11): oss << "Dec"; break;
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
    time_t rawtime = time(NULL);
    struct tm* date = localtime(&rawtime);

    ostringstream oss;
    oss << date->tm_year + 1900 << setfill('0') << setw(2) << date->tm_mon + 1 << setfill('0') << setw(2) << date->tm_mday;
    return oss.str();
}

void PLogger::writeLog(int lv, const char* funcName, int line, const char* str)
{
    string filepath = m_FileName + m_FileFormat;
    ofstream fout(filepath, std::ios::app);
    string timeStamp = getTimestamp();

    if(fout.fail())
    {
        cerr<<"Error code on fail to open file"<<endl;
        return;
    }

    char level[MAX_LENGTH];
    level[0] = '\0';
    switch (lv)
    {
    case(LOG_LEVEL_FATAL): strncat(level, "[FATAL]", MAX_LENGTH-1); break;
    case(LOG_LEVEL_ERROR): strncat(level, "[ERROR]", MAX_LENGTH-1); break;
    case(LOG_LEVEL_INFO): strncat(level, "[INFO] ", MAX_LENGTH-1); break;
    case(LOG_LEVEL_TRACE): strncat(level, "[TRACE]", MAX_LENGTH-1); break;
    }

    fout<<level<<" "<<timeStamp.c_str()<<" "<<"["<<funcName<<":"<<line<<"] : "<<str<<endl;

    if (this->logLevel >= lv)
    {
        cout<<level<<" "<<timeStamp.c_str()<<" "<<"["<<funcName<<":"<<line<<"] : "<<str<<endl;
    }

    fout.close();
    splitFile();
    return;
}

int32_t PLogger::fileSize(string filename)
{
    int32_t reVal = -1;
    struct stat sb {};

    if (0 == stat(filename.c_str(), &sb))
    {
        reVal = sb.st_size;
    }
    else
    {
        reVal = -1;
    }
    return reVal;
}

void PLogger::splitFile()
{
    if (fileSize(m_FileName+m_FileFormat) > MAX_FILE_SIZE * 1024) { // If it is over 100000kb, create a new file.
        
        string temp = getLogFileName();      
        int re = strncmp(m_FileName.c_str(), temp.c_str(), temp.size());
        
        if( re < 0) //If the size of the string passed as the first argument is smaller than the string passed as the second argument ex) aab < aac
        {
            m_FileName = temp;
            m_FileCount = 0;
        }
        else // If the size of the string passed as the first argument is greater than or equal to the string passed as the second argument ex) aab > aaa or aaa == aaa
        {
            if(m_FileCount < INT32_MAX)
                m_FileCount++;
            else
                m_FileCount = 0;
            m_FileName = temp +"_"+ std::to_string(m_FileCount);
        }
    }
}
