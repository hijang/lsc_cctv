#include <iostream>
#include <string>
#include <chrono>

#include <experimental/filesystem>

#include <NvInfer.h>
#include <NvInferPlugin.h>
#include <l2norm_helper.h>
#include <opencv2/core/cuda.hpp>
#include <opencv2/cudawarping.hpp>
#include "faceNet.h"
#include "mtcnn.h"
#include "cctvCrypto.h"

#include <termios.h>
#include <signal.h>

using namespace nvinfer1;
using namespace nvuffparser;

namespace fs = std::experimental::filesystem;

const string makeEncoded(const string& str)
{
    char* enc_str = encrypt_filename(str.c_str());
    string encrypted_str(enc_str);
    if (enc_str) {
        free(enc_str);
    }
    return encrypted_str;
}

const string sanitize(const string& name)
{
    string filtered;
    std::copy_if(begin(name), end(name), std::back_inserter(filtered), [](string::value_type c){return c != '/';} );

    return filtered;
}

fs::path makePersonImagePath(const string name)
{
    const fs::path imageStoragePath = fs::canonical("../imgs/"); // FIXME: 하드 코딩
    std::cout << "imageStorePath: " << imageStoragePath.c_str() << std::endl;
    fs::path imagePath = imageStoragePath / makeEncoded(name);

    return imagePath;
}

bool addAuthorized(const string inputImagePath, const string personName)
{
    Logger gLogger = Logger();
    // Register default TRT plugins (e.g. LRelu_TRT)
    if (!initLibNvInferPlugins(&gLogger, ""))
    {
        return false;
    }

    // USER DEFINED VALUES
    const string uffFile = "../facenetModels/facenet.uff";
    const string engineFile = "../facenetModels/facenet.engine";

    DataType dtype = DataType::kHALF;
    //DataType dtype = DataType::kFLOAT;
    bool serializeEngine = true;
    int batchSize = 1;
    int videoFrameWidth = 640;
    int videoFrameHeight = 480;

    int maxFacesPerScene = 8;
    float knownPersonThreshold = 1.;
    bool isCSICam = true;

    // init facenet
    FaceNetClassifier faceNet = FaceNetClassifier(gLogger, dtype, uffFile, engineFile, batchSize, serializeEngine,
                                                  knownPersonThreshold, maxFacesPerScene, videoFrameWidth, videoFrameHeight);
    // init mtCNN
    mtcnn mtCNN(videoFrameHeight, videoFrameWidth);

    // get embeddings of known faces
    cv::Mat image;
    loadInputImage(inputImagePath, image, videoFrameWidth, videoFrameHeight);
    std::vector<struct Bbox> outputBbox = mtCNN.findFace(image);

    if (outputBbox.empty())
    {
        std::cout << "invalid picture." << std::endl;
        return false;
    }

    // TODO: 경로 처리 시 input validation 필요
    do_crypt_file(inputImagePath.c_str(), makePersonImagePath(personName).c_str(), 1 /*encrypt*/);

    return true;
}

bool removeAuthorized(const string name)
{
    fs::path imagePath = makePersonImagePath(name);
    std::cout << "imagePath: " << imagePath.c_str() << std::endl;
    return fs::remove(imagePath);
}

int test_main()
{
    std::cout << sanitize("/etc/before") << std::endl;

    std::cout << makePersonImagePath("jeff") << std::endl;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s [command] ([filename] [name]) | [name] \n", argv[0]);
        return -1;
    }

    const string command = argv[1];
    if (command == "add" && argc == 4)
    {
        fs::path filename = argv[2];
        const string name = argv[3];

        if (filename.empty() || fs::file_size(filename) == 0) {
            std::cerr << "Fail to parsing parameter." << std::endl;
            return -1;
        }

        if (!filename.is_absolute()) {
            filename = fs::current_path() / filename;
        }

        fs::current_path("/home/cctv/work/lsc_cctv/LgFaceRecDemoTCP_Jetson_NanoV2/build/");

        bool result = addAuthorized(filename, argv[3]);
        if (!result)
            std::cerr << "failed to add authorized person. " << argv[2] << " " << argv[3] << std::endl;
    }
    else if (command == "remove" && argc == 3)
    {
        fs::current_path("/home/cctv/work/lsc_cctv/LgFaceRecDemoTCP_Jetson_NanoV2/build/");
        bool result = removeAuthorized(argv[2]);
        if (!result)
            std::cerr << "failed to remove authorized person. " << argv[2] << std::endl;
    }
    else
    {
        cerr << R"(invalid command. use 'add' or 'remove')" << "\n";
        return -1;
    }

    return 0;
}
