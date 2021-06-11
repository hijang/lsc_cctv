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
#include "sslConnect.h"

#if  defined(_WIN32) || defined(_WIN64)
#pragma comment (lib, "Ws2_32.lib")
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#define  CLOSE_SOCKET closesocket
#define  SOCKET_FD_TYPE SOCKET
#define  BAD_SOCKET_FD INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <unistd.h>
#define  CLOSE_SOCKET close
#define  SOCKET_FD_TYPE int
#define  BAD_SOCKET_FD  -1
#endif

#include <cstdio>

using namespace cv;
using namespace std;

#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }

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


    SslConnect* connection = new SslConnect;
    {       
        if (!connection->loadCertification()) {
            printf("Load server certification is faled \n");
            return(-1);
        }
        else {
            printf("Load server certification is success \n");
        }
    }

    int err;
    int listen_sd;

    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sd, "socket");

    struct sockaddr_in sa_serv;
    memset(&sa_serv, 0x00, sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons((atoi(argv[1])));

    err = ::bind(listen_sd, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
    CHK_ERR(err, "bind failed\n");

    err = listen(listen_sd, 5);
    CHK_ERR(err, "listen failed\n");

    printf("Waiting for connection from client \n");
    
    struct sockaddr_in sa_cli;
    socklen_t client_len = sizeof(sa_cli);
    int sd = accept(listen_sd, (struct sockaddr*)&sa_cli, &client_len);
    CHK_ERR(sd, "accept");
    closesocket(listen_sd);

    printf("Connection from %1x, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);


    /*
    if ((TcpListenPort = OpenTcpListenPort(atoi(argv[1]))) == NULL)  // Open UDP Network port
    {
        printf("OpenTcpListenPortFailed\n");
        return(-1);
    }
    */
    printf("Listening for connections\n");
    if (!connection->acceptConnection(sd)) {
        printf("verify certification is failed \n");
        exit(-1);
    }
    else {
        printf("client is connected and verified \n");
    }

    clilen = sizeof(cli_addr);



    /*
    if ((TcpConnectedPort = AcceptTcpConnection(TcpListenPort, &cli_addr, &clilen)) == NULL)
    {
        printf("AcceptTcpConnection Failed\n");
        return(-1);
    }
    */

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
        if (connection->sslWriteFromImageToJpeg(image) < 0)  break;
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
