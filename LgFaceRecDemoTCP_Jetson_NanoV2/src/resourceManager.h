#ifndef RESOURCE_MANAGER_H
#define RESOURCE_MANAGER_H

#include "sslConnect.h"
#include <cstddef>

class ResourceManager{
private:
    ResourceManager();
    ~ResourceManager();

    static ResourceManager* m_instance;

public:
    static ResourceManager* getInstance();
    void destroyResource();

    SslConnect* m_sslconnect;
    int sd;
};

#endif //RESOURCE_MANAGER_H
