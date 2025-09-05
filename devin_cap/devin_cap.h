#ifndef DEVIN_CAP_H
#define DEVIN_CAP_H

#include <pcap.h>
#include <winsock2.h>
#include <memory>
#include <vector>
#include "wintun/include/wintun.h"
#include "lockfree_queue.h"
#include "packet_buffer.h"
#include "packet_data.h"

// 定义常量
#define TARGET_IP "26.81.236.2"
#define DEVICE_NAME "Radmin" // 适配器描述中包含的关键字
#define UDP_FORWARD_IP "192.168.88.1"
#define UDP_FORWARD_PORT 11999
#define UDP_LISTEN_PORT 11999

// 全局变量声明
extern pcap_t* g_capture_handle; // 用于发送回注包的句柄
extern HANDLE g_udp_thread_handle; // UDP线程句柄
extern volatile bool g_running; // 控制程序运行状态
extern SOCKET g_forward_socket; // 用于UDP转发的Socket
extern WINTUN_SESSION_HANDLE g_session;

// 无锁队列用于优化数据包处理
extern LockFreeQueue<PacketData>* g_packet_queue;  // 用于存储从网络捕获的数据包
extern LockFreeQueue<PacketData>* g_udp_packet_queue;  // 用于存储从UDP接收的数据包

// 函数声明
int wintun_send(const uint8_t* packet, size_t len);

#endif // DEVIN_CAP_H