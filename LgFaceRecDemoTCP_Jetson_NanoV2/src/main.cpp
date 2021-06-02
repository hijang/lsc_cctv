#include <iostream>
#include <string>
#include <chrono>
#include <NvInfer.h>
#include <NvInferPlugin.h>
#include <l2norm_helper.h>
#include <opencv2/core/cuda.hpp>
#include <opencv2/cudawarping.hpp>
#include "faceNet.h"
#include "videoStreamer.h"
#include "network.h"
#include "mtcnn.h"

#include "NetworkTCP.h"
#include "TcpSendRecvJpeg.h"
#include <termios.h>

int kbhit()
{
    struct timeval tv = { 0L, 0L };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    return select(1, &fds, NULL, NULL, &tv);
}

int getch()
{
    int r;
    unsigned char c;
    if ((r = read(0, &c, sizeof(c))) < 0) {
        return r;
    } else {
        return c;
    }
}
// Uncomment to print timings in milliseconds
// #define LOG_TIMES

using namespace nvinfer1;
using namespace nvuffparser;


int main(int argc, char *argv[])
{
   TTcpListenPort    *TcpListenPort;
   TTcpConnectedPort *TcpConnectedPort;
   struct sockaddr_in cli_addr;
   socklen_t          clilen;
   bool               UseCamera=false;

   if (argc <2) 
    {
       fprintf(stderr,"usage %s [port] [filename]\n", argv[0]);
       exit(0);
    }

   if (argc==2) UseCamera=true;


    Logger gLogger = Logger();
    // Register default TRT plugins (e.g. LRelu_TRT)
    if (!initLibNvInferPlugins(&gLogger, "")) { return 1; }

    // USER DEFINED VALUES
    const string uffFile="../facenetModels/facenet.uff";
    const string engineFile="../facenetModels/facenet.engine";
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
    
    VideoStreamer *videoStreamer;

    // init opencv stuff
    if (UseCamera)  videoStreamer = new VideoStreamer(0, videoFrameWidth, videoFrameHeight, 60, isCSICam);
    else videoStreamer = new VideoStreamer(argv[2], videoFrameWidth, videoFrameHeight);



    cv::Mat frame;

    // init mtCNN
    mtcnn mtCNN(videoFrameHeight, videoFrameWidth);

    //init Bbox and allocate memory for "maxFacesPerScene" faces per scene
    std::vector<struct Bbox> outputBbox;
    outputBbox.reserve(maxFacesPerScene);

    // get embeddings of known faces
    std::vector<struct Paths> paths;
    cv::Mat image;
    getFilePaths("../imgs", paths);
    for(int i=0; i < paths.size(); i++) {
        loadInputImage(paths[i].absPath, image, videoFrameWidth, videoFrameHeight);
        outputBbox = mtCNN.findFace(image);
        std::size_t index = paths[i].fileName.find_last_of(".");
        std::string rawName = paths[i].fileName.substr(0,index);
        faceNet.forwardAddFace(image, outputBbox, rawName);
        faceNet.resetVariables();
    }
    outputBbox.clear();


   if  ((TcpListenPort=OpenTcpListenPort(atoi(argv[1])))==NULL)  // Open TCP Network port
     {
       printf("OpenTcpListenPortFailed\n");
       return(-1); 
     }

    
   clilen = sizeof(cli_addr);
    
   printf("Listening for connections\n");

   if  ((TcpConnectedPort=AcceptTcpConnection(TcpListenPort,&cli_addr,&clilen))==NULL)
     {  
       printf("AcceptTcpConnection Failed\n");
       return(-1); 
     }

   printf("Accepted connection Request\n");

     cv::cuda::GpuMat src_gpu, dst_gpu;
     cv::Mat dst_img;
    // loop over frames with inference
    auto globalTimeStart = chrono::steady_clock::now();
    
    while (true) {
        videoStreamer->getFrame(frame);
        if (frame.empty()) {
            std::cout << "Empty frame! Exiting...\n Try restarting nvargus-daemon by "
                         "doing: sudo systemctl restart nvargus-daemon" << std::endl;
            break;
        }
       // Create a destination to paint the source into.
       dst_img.create(frame.size(), frame.type());

      // Push the images into the GPU
      if (UseCamera)
        {
         src_gpu.upload(frame);
         cv::cuda::rotate(src_gpu, dst_gpu, src_gpu.size(), 180, src_gpu.size().width, src_gpu.size().height);
         dst_gpu.download(frame);
        }

        auto startMTCNN = chrono::steady_clock::now();
        outputBbox = mtCNN.findFace(frame);
        auto endMTCNN = chrono::steady_clock::now();
        auto startForward = chrono::steady_clock::now();
        faceNet.forward(frame, outputBbox);
        auto endForward = chrono::steady_clock::now();
        auto startFeatM = chrono::steady_clock::now();
        faceNet.featureMatching(frame);
        auto endFeatM = chrono::steady_clock::now();
        faceNet.resetVariables();
        
        if (TcpSendImageAsJpeg(TcpConnectedPort,frame)<0)  break;
        //cv::imshow("VideoSource", frame);
        nbFrames++;
        outputBbox.clear();
        frame.release();
        if (kbhit())
          {
          // Stores the pressed key in ch
           char keyboard =  getch();

        if (keyboard == 'q') break;
        else if(keyboard == 'n') 
          {
         
            auto dTimeStart = chrono::steady_clock::now();
            videoStreamer->getFrame(frame);
            // Create a destination to paint the source into.
            dst_img.create(frame.size(), frame.type());

            // Push the images into the GPU
            src_gpu.upload(frame);
            cv::cuda::rotate(src_gpu, dst_gpu, src_gpu.size(), 180, src_gpu.size().width, src_gpu.size().height);
            dst_gpu.download(frame);

            outputBbox = mtCNN.findFace(frame);
            if (TcpSendImageAsJpeg(TcpConnectedPort,frame)<0)  break;
            //cv::imshow("VideoSource", frame);
            faceNet.addNewFace(frame, outputBbox);
            auto dTimeEnd = chrono::steady_clock::now();
            globalTimeStart += (dTimeEnd - dTimeStart);
            
          }
         }


        #ifdef LOG_TIMES
        std::cout << "mtCNN took " << std::chrono::duration_cast<chrono::milliseconds>(endMTCNN - startMTCNN).count() << "ms\n";
        std::cout << "Forward took " << std::chrono::duration_cast<chrono::milliseconds>(endForward - startForward).count() << "ms\n";
        std::cout << "Feature matching took " << std::chrono::duration_cast<chrono::milliseconds>(endFeatM - startFeatM).count() << "ms\n\n";
        #endif  // LOG_TIMES
    }
  
    auto globalTimeEnd = chrono::steady_clock::now();


    videoStreamer->release();

    auto milliseconds = chrono::duration_cast<chrono::milliseconds>(globalTimeEnd-globalTimeStart).count();
    double seconds = double(milliseconds)/1000.;
    double fps = nbFrames/seconds;

    std::cout << "Counted " << nbFrames << " frames in " << double(milliseconds)/1000. << " seconds!" <<
              " This equals " << fps << "fps.\n";

    return 0;
}

