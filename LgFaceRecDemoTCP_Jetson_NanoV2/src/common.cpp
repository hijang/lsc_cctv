//
// Created by zhou on 18-4-30.
//

#include "common.h"
#include "cctvCrypto.h"

#include<iostream>
#include<fstream>

void* safeCudaMalloc(size_t memSize)
{
    void* deviceMem;
    CHECK(cudaMalloc(&deviceMem, memSize));
    if (deviceMem == nullptr)
    {
        std::cerr << "Out of memory" << std::endl;
        exit(1);
    }
    return deviceMem;
}


std::vector<std::pair<int64_t, nvinfer1::DataType>>
calculateBindingBufferSizes(const nvinfer1::ICudaEngine& engine, int nbBindings, int batchSize)
{
    std::vector<std::pair<int64_t, nvinfer1::DataType>> sizes;
    for (int i = 0; i < nbBindings; ++i)
    {
        nvinfer1::Dims dims = engine.getBindingDimensions(i);
        nvinfer1::DataType dtype = engine.getBindingDataType(i);

        int64_t eltCount = volume(dims) * batchSize;
        sizes.push_back(std::make_pair(eltCount, dtype));
    }

    return sizes;
}


inline int64_t volume(const nvinfer1::Dims& d)
{
    int64_t v = 1;
    for (int64_t i = 0; i < d.nbDims; i++)
        v *= d.d[i];
    return v;
}


void getFilePaths(std::string imagesPath, std::vector<struct Paths>& paths) {
    std::cout << "Parsing Directory: " << imagesPath << std::endl;
    DIR *dir;
    struct dirent *entry;
    if ((dir = opendir (imagesPath.c_str())) != NULL) {
        while ((entry = readdir (dir)) != NULL) {
            std::string readmeCheck(entry->d_name);
            if (entry->d_type != DT_DIR && readmeCheck != "README.md") {
                struct Paths tempPaths;
                tempPaths.fileName = std::string(entry->d_name);
                tempPaths.absPath = imagesPath + "/" + tempPaths.fileName;
                paths.push_back(tempPaths);
            }
        }
        closedir (dir);
    }
}


void loadInputImage(std::string inputFilePath, cv::Mat& image, int videoFrameWidth, int videoFrameHeight) {
    image = cv::imread(inputFilePath.c_str());
    cv::resize(image, image, cv::Size(videoFrameWidth, videoFrameHeight));
}

void loadInputImageSecure(std::string inputFilePath, cv::Mat& image, int videoFrameWidth, int videoFrameHeight) {
    unsigned char *buf = NULL;
    unsigned char *dec_buf = NULL;
    int img_size = readFileSize(inputFilePath);
    int dec_size = 0;

    if (img_size == 0) {
      printf("load image size of file(%s) is failed \n", inputFilePath.c_str());
      exit(1);
    } else {
      printf("load image size of file(%s)(%u) is success \n", inputFilePath.c_str(), img_size);
    }

    buf = (unsigned char*) malloc(img_size * sizeof(char));

    if (buf == NULL) {
      printf("malloc is failed \n");
      exit(1);
    }

    if (!do_crypt_buf(inputFilePath.c_str(), buf, &dec_size, 0)) {
      printf("decryption failed\n");
      free(buf);
      exit(1);
    }

    dec_buf = (unsigned char*) malloc(dec_size);
    memset(dec_buf, 0x00, dec_size);
    memcpy(dec_buf, buf, dec_size);

    std::vector<unsigned char> buffer(dec_buf, dec_buf + dec_size);
    image = cv::imdecode(buffer, 1);
    cv::resize(image, image, cv::Size(videoFrameWidth, videoFrameHeight));
    free(buf);
    free(dec_buf);
}

unsigned int readFileSize(std::string filePath)
{
    unsigned int size = 0;
    std::ifstream file;

    if (filePath.empty())
        return 0;

    file.open(filePath.c_str(), std::ios::binary);

    if (!file.is_open())
        return 0;

    file.seekg (0, std::ios::end);
    size = file.tellg();
    file.seekg (0, std::ios::beg);
    file.close();
    return size;
}
