#include "devin_cap.h"
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "lockfree_queue.h"
#include "packet_data.h"
#include <chrono>
#include <iostream>
#include <iomanip>

// 前向声明
extern LockFreeQueue<PacketData>* g_packet_queue;
extern LockFreeQueue<PacketData>* g_udp_packet_queue;
extern volatile bool g_running;
extern pcap_t* g_capture_handle;
extern SOCKET g_forward_socket;
extern WINTUN_SESSION_HANDLE g_session;

// 新的线程函数1：专门处理从网络捕获并需要转发的UDP数据包
unsigned __stdcall capture_forward_thread_function(void* param) {
    UNREFERENCED_PARAMETER(param);

    while (g_running) {
        // 处理从网络捕获并需要转发的UDP数据包
        auto packet_ptr = g_packet_queue ? g_packet_queue->dequeue() : nullptr;
        if (packet_ptr) {
            // 输出处理时间戳
            std::cout << "[PROCESS CAPTURE] Timestamp: " << getHighResTimestamp() << std::endl;
            
            // 发送数据包
            SOCKET udp_socket = g_forward_socket;
            sockaddr_in dest_addr;
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = htons(UDP_FORWARD_PORT);
            inet_pton(AF_INET, UDP_FORWARD_IP, &dest_addr.sin_addr); // Windows版本

            int sent_bytes = sendto(udp_socket, (const char*)packet_ptr->data.data(), (int)packet_ptr->data.size(), 0,
                (sockaddr*)&dest_addr, sizeof(dest_addr));
            if (sent_bytes == SOCKET_ERROR) {
                // fprintf(stderr, "UDP send failed: %d\n", WSAGetLastError());
                // 可选：打印错误，但不中断主流程
            }
            
            // 将PacketData对象返回到内存池
            PacketDataPool::release(std::move(packet_ptr));
        }
        else {
            // 队列为空，短暂休眠以避免忙等待
            Sleep(1);
        }
    }

    printf("Capture Forward Thread: Exiting.\n");
    _endthreadex(0);
    return 0;
}

// 新的线程函数2：专门处理从UDP接收并需要注入网络的数据包
unsigned __stdcall udp_inject_thread_function(void* param) {
    UNREFERENCED_PARAMETER(param);

    while (g_running) {
        // 处理从UDP接收并需要注入网络的数据包
        auto packet_ptr = g_udp_packet_queue ? g_udp_packet_queue->dequeue() : nullptr;
        if (packet_ptr) {
            // 输出处理时间戳
            std::cout << "[PROCESS UDP] Timestamp: " << getHighResTimestamp() << std::endl;
            
            // --- 将收到的原始数据通过 Npcap/Wintun 发送回网络 ---
            if (g_capture_handle && packet_ptr->data.size() > 0) {
                // 直接发送收到的原始字节流，假设它是一个完整的以太网帧
                wintun_send(packet_ptr->data.data(), packet_ptr->data.size());
            }
            
            // 将PacketData对象返回到内存池
            PacketDataPool::release(std::move(packet_ptr));
        }
        else {
            // 队列为空，短暂休眠以避免忙等待
            Sleep(1);
        }
    }

    printf("UDP Inject Thread: Exiting.\n");
    _endthreadex(0);
    return 0;
}