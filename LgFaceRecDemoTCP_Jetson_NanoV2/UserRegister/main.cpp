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

#include <termios.h>
#include <signal.h>

using namespace nvinfer1;
using namespace nvuffparser;

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		fprintf(stderr, "usage %s [port] [securedmode] [filename]\n", argv[0]);
		fprintf(stderr, "[securedmode] : non-secure-0/secure mode-1\n");
		exit(0);
	}

	Logger gLogger = Logger();
	// Register default TRT plugins (e.g. LRelu_TRT)
	if (!initLibNvInferPlugins(&gLogger, ""))
	{
		return 1;
	}

	// USER DEFINED VALUES
	const string uffFile = "../facenetModels/facenet.uff";
	const string engineFile = "../facenetModels/facenet.engine";
	DataType dtype = DataType::kHALF;
	//DataType dtype = DataType::kFLOAT;
	bool serializeEngine = true;
	int batchSize = 1;
	int nbFrames = 0;
	// int videoFrameWidth =1280;
	// int videoFrameHeight =720;
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

	//init Bbox and allocate memory for "maxFacesPerScene" faces per scene
	std::vector<struct Bbox> outputBbox;
	outputBbox.reserve(maxFacesPerScene);

	// get embeddings of known faces
	struct Paths path;
	cv::Mat image;
	
	loadInputImage(path.absPath, image, videoFrameWidth, videoFrameHeight);
	outputBbox = mtCNN.findFace(image);

	outputBbox.clear();


	return 0;
}
