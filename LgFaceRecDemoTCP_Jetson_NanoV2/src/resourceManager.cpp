#include "resourceManager.h"
#include <unistd.h>

ResourceManager* ResourceManager::m_instance = nullptr;

ResourceManager::ResourceManager()
    : m_sslconnect(NULL)
    , sd(0)
{
}

ResourceManager::~ResourceManager()
{
}

ResourceManager* ResourceManager::getInstance()
{
    if (m_instance == NULL)
        m_instance = new ResourceManager();
    return m_instance;
}

void ResourceManager::destroyResource(void)
{
    if (sd)
        close(sd);
    if (m_sslconnect)
        delete m_sslconnect;
}
