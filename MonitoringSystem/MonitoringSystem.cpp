//------------------------------------------------------------------------------------------------
// File: RecvImageTCP.cpp
// Project: LG Exec Ed Program
// Versions:
// 1.0 April 2017 - initial version
// This program receives a jpeg image via a TCP Stream and displays it. 
//----------------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <iostream>
#include "NetworkTCP.h"
#include "TcpSendRecvJpeg.h"
#include "SslConnect.h"

#define SECURE_MODE         (true)
#define MAX_CONNECT_TRIAL   (100)

using namespace cv;
using namespace std;
//----------------------------------------------------------------
// main - This is the main program for the RecvImageUDP demo 
// program  contains the control loop
//-----------------------------------------------------------------


int main(int argc, char* argv[])
{
    TTcpConnectedPort* TcpConnectedPort = NULL;
    SslConnect* ssl = NULL;
    bool retvalue;
    bool do_exit = false;
    int connect_trial = 0;

    if (argc != 3)
    {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }
#if (SECURE_MODE)
    ssl = new SslConnect();
    ssl->InitializeCtx();
#endif

    do {
        //  Try until connection established
        do {
            connect_trial++;
            printf("Tring to connect(%d)...\n", connect_trial);
            if ((TcpConnectedPort = OpenTcpConnection(argv[1], argv[2])) == NULL)  // Open TCP Network port
            {
                printf("Error on OpenTcpConnection\n");
                //  Terminate if it met maximum trial
                if (connect_trial == MAX_CONNECT_TRIAL)
                {
                    printf("Unable to connect. Terminate.\n");
                    if (ssl != NULL) {
                        delete ssl;
                        ssl = NULL;
                    }
                    return(-1);
                }
                Sleep(5000);
            }
            do_exit = (waitKey(10) != 'q');
        } while (TcpConnectedPort == NULL && !do_exit);
        connect_trial = 0;

        if (ssl != NULL && !ssl->Connect(TcpConnectedPort->ConnectedFd))
        {
            printf("Failed to Connect on SSL\n");
            break;
        }

        namedWindow("Server", WINDOW_AUTOSIZE);// Create a window for display.

        Mat Image;
        do {
            if (ssl != NULL)
            {
                retvalue = SslRecvImageAsJpeg(ssl->GetSSL(), &Image);
            }
            else
            {
                retvalue = TcpRecvImageAsJpeg(TcpConnectedPort, &Image);
            }
            if (retvalue) imshow("Server", Image); // If a valid image is received then display it
            else
            {
                printf("Invalid image\n");
                CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
                break;
            }
            do_exit = (waitKey(10) != 'q');
        } while (do_exit); // loop until user hits quit

        //  It server has been down, disconnect port
    } while (do_exit);

    printf(" Closing... \n");
    CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
    if (ssl != NULL)
    {
        delete ssl;
        ssl = NULL;
    }

    return 0;
}
//-----------------------------------------------------------------
// END main
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
