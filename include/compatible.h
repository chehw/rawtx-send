#ifndef _COMPATIBLE_H_
#define _COMPATIBLE_H_

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif


#endif
