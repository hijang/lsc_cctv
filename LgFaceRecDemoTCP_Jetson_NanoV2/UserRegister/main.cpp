#include <iostream>
#include <string>
#include <chrono>

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

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		fprintf(stderr, "usage: %s [command] [filename] [name]\n", argv[0]);
		return -1;
	}

	const string command = argv[1];
	if (command != "add" && command != "remove")
	{
		cerr << R"(invalid command. use 'add' or 'remove')" << "\n";
		return -1;
	}

	// TODO: input validation
	const string inputImagePath = argv[2];
	const string personName = argv[3];


	Logger gLogger = Logger();
	// Register default TRT plugins (e.g. LRelu_TRT)
	if (!initLibNvInferPlugins(&gLogger, ""))
	{
		return 1;
	}

	// USER DEFINED VALUES
	const string uffFile = "../facenetModels/facenet.uff";
	const string engineFile = "../facenetModels/facenet.engine";
	const string imageStoragePath = "../imgs/";


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
		return -1;
	}
	
	// TODO: 경로 처리 시 input validation 필요
	do_crypt_file(inputImagePath.c_str(), (imageStoragePath + personName + ".png").c_str(), 1 /*encrypt*/);


	return 0;
}
