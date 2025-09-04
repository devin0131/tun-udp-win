#ifndef PACKET_SEND_THREAD_H
#define PACKET_SEND_THREAD_H

#include <process.h>

// 线程函数声明
unsigned __stdcall capture_forward_thread_function(void* param);
unsigned __stdcall udp_inject_thread_function(void* param);

#endif // PACKET_SEND_THREAD_H