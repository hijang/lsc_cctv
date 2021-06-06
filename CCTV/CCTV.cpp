//------------------------------------------------------------------------------------------------
// This program Sends a jpeg image From the local video via a TCP Stream to a remote destination. 
//----------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <iostream>
#include <memory>
#include "NetworkTCP.h"
#include "TcpSendRecvJpeg.h"

#include "videoStreamer.h"

using namespace cv;
using namespace std;



//----------------------------------------------------------------
// main - This is the main program for the RecvImageUDP demo 
// program  contains the control loop
//---------------------------------------------------------------

int main(int argc, char* argv[])
{

    Mat                image;          // camera image in Mat format 
    TTcpListenPort* TcpListenPort;
    TTcpConnectedPort* TcpConnectedPort;
    struct sockaddr_in cli_addr;
    socklen_t          clilen;

    if (argc != 3)
    {
        fprintf(stderr, "usage %s port videofile\n", argv[0]);
        exit(0);
    }


    int capture_width = 1280;
    int capture_height = 720;
    int display_width = 1280;
    int display_height = 720;
    int framerate = 60;
    int flip_method = 2;
    std::unique_ptr<VideoStreamer> videoStreamer(new VideoStreamer(argv[2], capture_width, capture_height));


    if ((TcpListenPort = OpenTcpListenPort(atoi(argv[1]))) == NULL)  // Open UDP Network port
    {
        printf("OpenTcpListenPortFailed\n");
        return(-1);
    }


    clilen = sizeof(cli_addr);

    printf("Listening for connections\n");

    if ((TcpConnectedPort = AcceptTcpConnection(TcpListenPort, &cli_addr, &clilen)) == NULL)
    {
        printf("AcceptTcpConnection Failed\n");
        return(-1);
    }

    printf("Accepted connection Request\n");


    int key = 0;
    do
    {
        videoStreamer->getFrame(image);
        // check if we succeeded
        if (image.empty())
        {
            printf("ERROR! blank frame grabbed\n");
            continue;
        }

        // Send processed UDP image
        if (TcpSendImageAsJpeg(TcpConnectedPort, image) < 0)  break;
        key = (waitKey(10) & 0xFF);
        printf("%d\n", key);
    } while (key != 'q'); // loop until user hits quit

    CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
    CloseTcpListenPort(&TcpListenPort);  // Close listen port

    return 0;
}
//-----------------------------------------------------------------
// END main
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
