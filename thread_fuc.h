#ifndef THREAD
#define THREAD

#include "headers.h"
#include "struct.h"
#include "send.h"
#include "util.h"

DWORD WINAPI send_thread(void * param);
DWORD WINAPI relay_thread(void *param);

#endif