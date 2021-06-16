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
#include "sslConnect.h"
#include "logger.h"
#include "cctvCrypto.h"
#include <termios.h>
#include <signal.h>

#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }

#define PORT_NUM    (5000)

void signalHandler( int signum ) {
    logg.fatal("CCTV system will be shut-down now!\n");
    exit(signum);
}

int kbhit()
{
    struct timeval tv = { 0L, 0L };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    return select(1, &fds, NULL, NULL, &tv);
}

void clearInputBuffer(void)
{
    while (getchar() != '\n');
    return;
}

int getch()
{
    int r;
    unsigned char c;
    if ((r = read(0, &c, sizeof(c))) < 0) {
        clearInputBuffer();
        return r;
    } else {
        clearInputBuffer();
        return c;
    }
}
// Uncomment to print timings in milliseconds
// #define LOG_TIMES

using namespace nvinfer1;
using namespace nvuffparser;


int main(int argc, char *argv[])
{
    int sd;
    int secureMode = 1;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    socklen_t client_len;

    TTcpListenPort    *TcpListenPort = NULL;
    TTcpConnectedPort *TcpConnectedPort = NULL;
    struct sockaddr_in cli_addr;
    socklen_t          clilen;
    bool               UseCamera=false;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signalHandler);

    SslConnect* connection = NULL;

    if (argc <2)
    {
        fprintf(stderr,"usage %s [securedmode:0/1] [filename]\n", argv[0]);
        fprintf(stderr,"[securedmode] : non-secure-0/secure mode-1\n");
        exit(0);
    }

    if (argc==2) UseCamera=true;
    if (atoi(argv[1]) == 0)
        secureMode = 0;

    std::string videoFile;
    if (argc==3)
    {
        videoFile = std::string(argv[2]);
        if (videoFile.empty() || access(videoFile.c_str(), F_OK) != 0) {
            fprintf(stderr,"File is not exist. Check file to play video file(%s) \n", argv[2]);
            exit(0);
        }
    }

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

    if (secureMode)
    {
        connection = new SslConnect;
        if (connection == NULL) {
            logg.fatal("Fail to create SslConnect.\n");
            fprintf(stderr, "Fail to start service [Internal Error : Fail to create SslConnect.]\n");
            return(-1);
        }
        if (!connection->loadCertification()) {
            logg.fatal("Loading server certification and private key is fail\n");
            fprintf(stderr, "Fail to start service [Internal Error : Load server cert/key is failed.\n");
            delete connection;
            return(-1);
        } else {
            logg.trace("Loading server certification and private key is success.\n");
        }
    }

    // init facenet
    FaceNetClassifier faceNet = FaceNetClassifier(gLogger, dtype, uffFile, engineFile, batchSize, serializeEngine,
            knownPersonThreshold, maxFacesPerScene, videoFrameWidth, videoFrameHeight);

    VideoStreamer *videoStreamer;

    // init opencv stuff
    if (UseCamera)  videoStreamer = new VideoStreamer(0, videoFrameWidth, videoFrameHeight, 60, isCSICam);
    else videoStreamer = new VideoStreamer(videoFile, videoFrameWidth, videoFrameHeight);

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
        char* rawName = NULL;
        loadInputImageSecure(paths[i].absPath, image, videoFrameWidth, videoFrameHeight);
        outputBbox = mtCNN.findFace(image);
        rawName = decrypt_filename(paths[i].fileName.c_str());
        faceNet.forwardAddFace(image, outputBbox, rawName);
        faceNet.resetVariables();
        free(rawName);
    }
    outputBbox.clear();

connection_wait:

    cv::cuda::GpuMat src_gpu, dst_gpu;
    cv::Mat dst_img;
    // loop over frames with inference
    auto globalTimeStart = chrono::steady_clock::now();

    if (secureMode)
    {
        int err;
        int listen_sd;

        listen_sd = socket(AF_INET, SOCK_STREAM, 0);
        CHK_ERR(listen_sd, "socket");

        memset(&sa_serv, 0x00, sizeof(sa_serv));
        sa_serv.sin_family = AF_INET;
        sa_serv.sin_addr.s_addr = INADDR_ANY;
        sa_serv.sin_port = htons(PORT_NUM);

        err = bind(listen_sd, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
        CHK_ERR(err, "bind failed\n");

        err = listen(listen_sd, 5);
        CHK_ERR(err, "listen failed\n");

        fprintf(stdout, "Waiting for connection from client.\n");

        client_len = sizeof(sa_cli);
        sd = accept(listen_sd, (struct sockaddr*)&sa_cli, &client_len);
        CHK_ERR(sd, "accept");
        close(listen_sd);

        logg.trace("Monitoring system is connected from %1x, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);

        if (!connection->acceptConnection(sd)) {
            logg.fatal("Fail to verify client for ssl connection.\n");
            fprintf(stderr, "Fail to verify client.\n");
            goto cleanup_and_wait;
        } else {
            logg.trace("client is connected and verified.\n");
        }
    }
    else
    {
        clilen = sizeof(cli_addr);
        fprintf(stdout, "Waiting for connection from client.\n");
        if  ((TcpListenPort=OpenTcpListenPort(PORT_NUM))==NULL)
        {
            fprintf(stderr, "OpenTcpListenPortFailed.\n");
            goto cleanup_and_wait;
        }

        if  ((TcpConnectedPort=AcceptTcpConnection(TcpListenPort,&cli_addr,&clilen))==NULL)
        {
            printf("AcceptTcpConnection Failed\n");
            goto cleanup_and_wait;
        }
        CloseTcpListenPort(&TcpListenPort);
    }

    fprintf(stdout, "Now streaming is started.\n");

    while (true) {
        videoStreamer->getFrame(frame);
        if (frame.empty()) {
            std::cout << "Empty frame! Exiting...\n Try restarting nvargus-daemon by "
                "doing: sudo systemctl restart nvargus-daemon" << std::endl;
            exit(-1);
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
        if (secureMode)
        {
            if (connection->sslWriteFromImageToJpeg(frame)<=0) goto cleanup_and_wait;
        }
        else
        {
            if (TcpSendImageAsJpeg(TcpConnectedPort,frame)<0)  goto cleanup_and_wait;
        }
        //cv::imshow("VideoSource", frame);
        nbFrames++;
        outputBbox.clear();
        frame.release();
        if (kbhit())
        {
            // Stores the pressed key in ch
            char keyboard =  getch();

            if (keyboard == 'q')
            {
                printf("Program will be shut-down. \n");
                goto finalize;
            }
            else if(keyboard == 'n')
            {
                printf("Try to add new person \n");
                auto dTimeStart = chrono::steady_clock::now();
                videoStreamer->getFrame(frame);
                // Create a destination to paint the source into.
                dst_img.create(frame.size(), frame.type());

                // Push the images into the GPU
                src_gpu.upload(frame);
                cv::cuda::rotate(src_gpu, dst_gpu, src_gpu.size(), 180, src_gpu.size().width, src_gpu.size().height);
                dst_gpu.download(frame);

                outputBbox = mtCNN.findFace(frame);
                if (secureMode)
                {
                    if (connection->sslWriteFromImageToJpeg(frame)<=0) goto cleanup_and_wait;
                }
                else
                {
                    if (TcpSendImageAsJpeg(TcpConnectedPort,frame)<0) goto cleanup_and_wait;
                }
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
cleanup_and_wait:
    if (sd) {
        close(sd);
        sd=0;
    }
    if (TcpConnectedPort) {
        CloseTcpConnectedPort(&TcpConnectedPort);
        TcpConnectedPort=NULL;
    }
    logg.trace("Connection is closed.\n");
    goto connection_wait;
finalize:
    auto globalTimeEnd = chrono::steady_clock::now();

    videoStreamer->release();

    auto milliseconds = chrono::duration_cast<chrono::milliseconds>(globalTimeEnd-globalTimeStart).count();
    double seconds = double(milliseconds)/1000.;
    double fps = nbFrames/seconds;

    std::cout << "Counted " << nbFrames << " frames in " << double(milliseconds)/1000. << " seconds!" <<
        " This equals " << fps << "fps.\n";

    if (connection)
        delete connection;
    close(sd);

    return 0;
}

