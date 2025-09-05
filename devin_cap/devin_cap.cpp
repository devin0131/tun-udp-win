// main.cpp - Npcap Capture Demo (Enhanced)
// 捕获发往 192.168.88.188:10999 的 UDP 流量，并进行 UDP 转发和回注

#include "lockfree_queue.h"
#include "packet_buffer.h"
#include "packet_data.h"
#include "packet_send_thread.h"
#include "wintun.h"
#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <netioapi.h>
#include <pcap.h>
#include <process.h> // For _beginthreadex
#include <sstream>
#include <stack>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>
#include <winsock2.h> // Windows Socket API
#include <ws2tcpip.h> // For sockaddr_in

#pragma comment(lib, "wpcap.lib")  // Link with Npcap library
#pragma comment(lib, "ws2_32.lib") // Link with Windows Sockets library
#pragma comment(lib, "iphlpapi.lib")

#define TARGET_IP "26.81.236.2"
#define DEVICE_NAME "Radmin" // 适配器描述中包含的关键字
#define UDP_FORWARD_IP "192.168.88.1"
#define UDP_FORWARD_PORT 11999
#define UDP_LISTEN_PORT 11999

// 全局变量 - 用于在捕获线程和UDP线程间共享数据
pcap_t *g_capture_handle = nullptr;       // 用于发送回注包的句柄
HANDLE g_udp_thread_handle = nullptr;     // UDP线程句柄
volatile bool g_running = true;           // 控制程序运行状态
SOCKET g_forward_socket = INVALID_SOCKET; // 用于UDP转发的Socket
WINTUN_SESSION_HANDLE g_session = NULL;
WINTUN_ADAPTER_HANDLE g_tun_adpter;

// 线程句柄
HANDLE capture_forward_thread_handle = nullptr; // 捕获转发线程句柄
HANDLE udp_inject_thread_handle = nullptr;      // UDP注入线程句柄

// 无锁队列用于优化数据包处理
LockFreeQueue<PacketData> *g_packet_queue =
    nullptr; // 用于存储从网络捕获的数据包
LockFreeQueue<PacketData> *g_udp_packet_queue =
    nullptr; // 用于存储从UDP接收的数据包

// 函数声明
void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header,
                    const u_char *pkt_data);
int initUdpSocket(bool &retFlag);
void print_packet_info(const struct pcap_pkthdr *header, const u_char *packet);
void parse_udp_packet(const u_char *packet, int packet_len);
unsigned __stdcall udp_thread_function(void *param); // UDP处理线程函数
unsigned __stdcall capture_forward_thread_function(
    void *param);                                           // 捕获转发线程函数
unsigned __stdcall udp_inject_thread_function(void *param); // UDP注入线程函数
void send_packet_via_npcap(const u_char *packet_data, int packet_len);
void send_packet_via_tun(const u_char *ip_packet, int ip_len);
void wintun_shutdown(void);
HMODULE InitializeWintun();
int wintun_send(const uint8_t *packet, size_t len);
int wintun_init(const WCHAR *adapter_name, const WCHAR *tunnel_name,
                const WCHAR *ip_str, int netmask_cidr);
BOOL enable_interface_forwarding(const WCHAR *adapter_name);

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

std::string getCurrentTimestamp() {
  // 获取当前时间点（高精度）
  const auto now = std::chrono::system_clock::now();

  // 转换为 system_time（用于获取时分秒）
  auto now_time_t = std::chrono::system_clock::to_time_t(now);
  auto now_ms = std::chrono::duration_cast<std::chrono::microseconds>(
      now.time_since_epoch());

  // 提取时、分、秒
  tm time_info = {};
#ifdef _WIN32
  localtime_s(&time_info, &now_time_t); // Windows 安全函数
#else
  localtime_r(&time_info, &time_info); // Linux
#endif

  // 计算毫秒和微秒部分
  long long us = now_ms.count() % 1000000; // 微秒 (0~999999)
  int seconds = time_info.tm_sec;
  int minutes = time_info.tm_min;
  int hours = time_info.tm_hour;

  // 使用 stringstream 格式化输出
  std::ostringstream oss;
  oss << std::setfill('0') << std::setw(2) << hours << ":" << std::setw(2)
      << minutes << ":" << std::setw(2) << seconds << "." << std::setw(6) << us;

  return oss.str();
}

int main() {
  WSADATA wsaData;
  pcap_if_t *all_devices = nullptr;
  pcap_if_t *device = nullptr;
  pcap_t *handle = nullptr;
  char error_buffer[PCAP_ERRBUF_SIZE];
  struct bpf_program filter_code;
  const char *filter_expression =
      "ip dst host " TARGET_IP
      " and udp and (dst port 10999 or dst port 10998)";
  int result;

  printf("=== Npcap Capture & Forward Demo ===\n");
  printf("Target: UDP packets to " TARGET_IP ":10999\n");
  printf("Forward: Captured packets -> %s:%d\n", UDP_FORWARD_IP,
         UDP_FORWARD_PORT);
  printf("Listen:  %s:%d -> Inject back to network\n", UDP_FORWARD_IP,
         UDP_LISTEN_PORT);
  printf("Adapter: " DEVICE_NAME "\n\n");

  // 初始化无锁队列
  g_packet_queue = new LockFreeQueue<PacketData>();
  g_udp_packet_queue = new LockFreeQueue<PacketData>();

  // 初始化 Windows Sockets
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    fprintf(stderr, "Error: WSAStartup failed.\n");
    return -1;
  }

  // 初始化 Wintun
  HMODULE wintun = InitializeWintun();
  if (!wintun) {
    fprintf(stderr, "Failed to load Wintun.dll\n");
    WSACleanup();
    return -1;
  }
  fprintf(stderr, "Wintun.dll loaded successfully.\n");

  wintun_init(L"DevinTun0", L"DevinTunnel", L"192.168.254.1", 24);

  // 0. 创建并绑定发送socket
  bool retFlag;
  int retVal = initUdpSocket(retFlag);
  if (retFlag)
    return retVal;

  // 1. 获取所有网络接口列表
  if (pcap_findalldevs(&all_devices, error_buffer) == -1) {
    fprintf(stderr, "Error finding devices: %s\n", error_buffer);
    WSACleanup();
    return -1;
  }

  // 2. 查找描述的适配器
  printf("Searching for adapter containing '%s'...\n", DEVICE_NAME);
  for (device = all_devices; device != nullptr; device = device->next) {
    if (device->description != nullptr &&
        strstr(device->description, DEVICE_NAME) != nullptr) {
      printf("FOUND! Using adapter: %s\n", device->description);
      break;
    }
  }

  if (device == nullptr) {
    fprintf(stderr, "ERROR: Adapter containing '%s' not found!\n", DEVICE_NAME);
    fprintf(stderr, "Available adapters:\n");
    for (pcap_if_t *d = all_devices; d != nullptr; d = d->next) {
      printf("  %s", d->name);
      if (d->description)
        printf(" (%s)", d->description);
      printf("\n");
    }
    pcap_freealldevs(all_devices);
    WSACleanup();
    return -1;
  }

  // 3. 打开选中的适配器进行捕获 (需要发送能力)
  handle = pcap_open_live(device->name, 262144, 1, 1, error_buffer);
  if (handle == nullptr) {
    fprintf(stderr, "Error opening adapter %s: %s\n", device->name,
            error_buffer);
    pcap_freealldevs(all_devices);
    WSACleanup();
    return -1;
  }
  pcap_set_immediate_mode(handle, 1);

  printf("Adapter '%s' opened successfully.\n", device->description);

  // 将全局句柄赋值，用于UDP线程发送
  g_capture_handle = handle;

  // 4. 编译 BPF 过滤器
  if (pcap_compile(handle, &filter_code, filter_expression, 1, 0) == -1) {
    fprintf(stderr, "Error compiling filter '%s': %s\n", filter_expression,
            pcap_geterr(handle));
    pcap_close(handle);
    pcap_freealldevs(all_devices);
    WSACleanup();
    return -1;
  }

  // 5. 应用过滤器
  if (pcap_setfilter(handle, &filter_code) == -1) {
    fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
    pcap_freecode(&filter_code);
    pcap_close(handle);
    pcap_freealldevs(all_devices);
    WSACleanup();
    return -1;
  }
  pcap_freecode(&filter_code);

  printf("BPF Filter applied: '%s'\n", filter_expression);

  // 6. 创建UDP处理线程
  g_udp_thread_handle = (HANDLE)_beginthreadex(nullptr, 0, udp_thread_function,
                                               nullptr, 0, nullptr);
  if (g_udp_thread_handle == nullptr) {
    fprintf(stderr, "Error creating UDP thread.\n");
    g_running = false;
    pcap_breakloop(handle); // 尝试中断主循环
    // 等待可能已创建的线程 (这里简化处理)
    if (g_udp_thread_handle)
      WaitForSingleObject(g_udp_thread_handle, INFINITE);
    pcap_close(handle);
    pcap_freealldevs(all_devices);
    WSACleanup();
    return -1;
  }

  // 7. 创建数据包发送线程（捕获转发线程）
  HANDLE capture_forward_thread_handle = (HANDLE)_beginthreadex(
      nullptr, 0, capture_forward_thread_function, nullptr, 0, nullptr);
  if (capture_forward_thread_handle == nullptr) {
    fprintf(stderr, "Error creating capture forward thread.\n");
    g_running = false;
    pcap_breakloop(handle); // 尝试中断主循环
    // 等待可能已创建的线程
    if (g_udp_thread_handle)
      WaitForSingleObject(g_udp_thread_handle, INFINITE);
    pcap_close(handle);
    pcap_freealldevs(all_devices);
    WSACleanup();
    return -1;
  }

  // 8. 创建UDP注入线程
  HANDLE udp_inject_thread_handle = (HANDLE)_beginthreadex(
      nullptr, 0, udp_inject_thread_function, nullptr, 0, nullptr);
  if (udp_inject_thread_handle == nullptr) {
    fprintf(stderr, "Error creating UDP inject thread.\n");
    g_running = false;
    pcap_breakloop(handle); // 尝试中断主循环
    // 等待可能已创建的线程
    if (g_udp_thread_handle)
      WaitForSingleObject(g_udp_thread_handle, INFINITE);
    if (capture_forward_thread_handle)
      WaitForSingleObject(capture_forward_thread_handle, INFINITE);
    pcap_close(handle);
    pcap_freealldevs(all_devices);
    WSACleanup();
    return -1;
  }

  printf("UDP thread started. Listening on port %d.\n", UDP_LISTEN_PORT);
  printf("STARTING CAPTURE... (Press Ctrl+C to stop)\n");
  printf("------------------------------------------------\n");

  // 7. 开始捕获循环
  result = pcap_loop(handle, -1, packet_handler, nullptr);

  if (result == -1) {
    fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
  } else if (result == -2) {
    printf("Capture stopped by user.\n");
  } else {
    printf("Capture finished. %d packets processed.\n", result);
  }

  // 8. 清理资源
  g_running = false; // 通知线程退出

  // 等待UDP线程结束
  if (g_udp_thread_handle) {
    WaitForSingleObject(g_udp_thread_handle, 5000); // 等待最多5秒
    CloseHandle(g_udp_thread_handle);
  }

  // 等待捕获转发线程结束
  if (capture_forward_thread_handle) {
    WaitForSingleObject(capture_forward_thread_handle, 5000); // 等待最多5秒
    CloseHandle(capture_forward_thread_handle);
  }

  // 等待UDP注入线程结束
  if (udp_inject_thread_handle) {
    WaitForSingleObject(udp_inject_thread_handle, 5000); // 等待最多5秒
    CloseHandle(udp_inject_thread_handle);
  }

  pcap_close(handle);
  pcap_freealldevs(all_devices);
  WSACleanup(); // 清理Windows Sockets
  wintun_shutdown();

  // 清理无锁队列
  if (g_packet_queue) {
    delete g_packet_queue;
    g_packet_queue = nullptr;
  }

  if (g_udp_packet_queue) {
    delete g_udp_packet_queue;
    g_udp_packet_queue = nullptr;
  }

  printf("Resources cleaned up. Exiting.\n");
  return 0;
}

int initUdpSocket(bool &retFlag) {
  retFlag = true;
  g_forward_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (g_forward_socket == INVALID_SOCKET) {
    fprintf(stderr, "Failed to create forward socket.\n");
    return -1;
  }

  sockaddr_in local_addr;
  local_addr.sin_family = AF_INET;
  local_addr.sin_port = htons(UDP_LISTEN_PORT);
  local_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(g_forward_socket, (sockaddr *)&local_addr, sizeof(local_addr)) ==
      SOCKET_ERROR) {
    fprintf(stderr, "Failed to bind forward socket on port %d: %d\n",
            UDP_LISTEN_PORT, WSAGetLastError());
    closesocket(g_forward_socket);
    g_forward_socket = INVALID_SOCKET;
    return -1;
  }

  printf("Forward socket bound to local port %d\n", UDP_LISTEN_PORT);
  retFlag = false;
  return 0;
}

// 回调函数 - 每当捕获到一个匹配的数据包，此函数就会被调用
void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header,
                    const u_char *pkt_data) {
  UNREFERENCED_PARAMETER(user);

  // 打印基础信息
  // print_packet_info(pkt_header, pkt_data);
  // parse_udp_packet(pkt_data, pkt_header->caplen);

  // --- 新增功能 1: 将捕获到的原始数据包通过UDP发送出去 ---
  if (g_running && pkt_data && pkt_header->caplen > 0) {
    // ✅ 1. 检查是否至少有 14 字节（MAC 头）
    if (pkt_header->caplen < 14) {
      return;
    }

    // ✅ 2. 获取 EtherType (bytes 12-13)
    uint16_t ether_type = (pkt_data[12] << 8) | pkt_data[13];

    // 可选：只转发 IPv4 数据包
    if (ether_type != 0x0800) {
      // 不是 IPv4，跳过（也可以处理 ARP 0x0806 等）
      return;
    }

    // ✅ 3. 剥离 MAC 头：从第 14 字节开始
    const u_char *ip_packet = pkt_data + 14;
    int ip_packet_len = pkt_header->caplen - 14;

    // 使用无锁队列优化，将数据包放入队列中，由专门的线程处理发送
    if (g_packet_queue) {
      // 使用零拷贝方法创建PacketData对象并入队
      auto packet_data =
          PacketData::create_shared((const uint8_t *)ip_packet, ip_packet_len);
      g_packet_queue->enqueue_shared(std::move(packet_data));
    }
  }
  // --- 功能 1 结束 ---
}

// 打印数据包基础信息
void print_packet_info(const struct pcap_pkthdr *header, const u_char *packet) {
  // struct tm* ltime;
  struct tm time_info;
  char timestr[16];
  time_t local_tv_sec = header->ts.tv_sec;

  if (localtime_s(&time_info, &local_tv_sec) == 0) {
    strftime(timestr, sizeof(timestr), "%H:%M:%S", &time_info);
    printf("[%s] CapPacktime: [%s.%06ld] Len: %d (Captured: %d)\n",
           getCurrentTimestamp().c_str(), timestr, header->ts.tv_usec,
           header->len, header->caplen);
  } else {
    printf("[Invalid Time] Len: %d (Captured: %d)\n", header->len,
           header->caplen);
  }
}

// 解析 UDP 数据包 (简化版)
void parse_udp_packet(const u_char *packet, int packet_len) {
  int ethernet_header_length = 14;
  int ip_header_length;
  int udp_header_length = 8;
  const u_char *ip_header;
  const u_char *udp_header;
  const u_char *payload;
  int payload_len;

  if (packet_len < ethernet_header_length + 20 + udp_header_length) {
    printf("  [Packet too short for UDP parsing]\n");
    return;
  }

  ip_header = packet + ethernet_header_length;
  ip_header_length = (ip_header[0] & 0x0F) * 4;

  if (ip_header[9] != 17) {
    printf("  [Not a UDP packet]\n");
    return;
  }

  udp_header = ip_header + ip_header_length;
  unsigned short src_port = ntohs(*(unsigned short *)(udp_header));
  unsigned short dst_port = ntohs(*(unsigned short *)(udp_header + 2));

  printf("  IP: %d.%d.%d.%d -> %d.%d.%d.%d | ", ip_header[12], ip_header[13],
         ip_header[14], ip_header[15], ip_header[16], ip_header[17],
         ip_header[18], ip_header[19]);
  printf("UDP: %u -> %u\n", src_port, dst_port);

  payload = udp_header + udp_header_length;
  payload_len = ntohs(*(unsigned short *)(udp_header + 4)) - udp_header_length;
  if (payload_len > 0 && payload < packet + packet_len) {
    printf("  Payload (%d bytes): ", payload_len);
    int print_len = (payload_len > 16) ? 16 : payload_len;
    for (int i = 0; i < print_len; i++) {
      printf("%02X ", payload[i]);
    }
    if (payload_len > 16)
      printf("...");
    printf("\n");
  }
}

// --- 新增功能 2: UDP处理线程函数 ---
unsigned __stdcall udp_thread_function(void *param) {
  UNREFERENCED_PARAMETER(param);

  SOCKET udp_socket = g_forward_socket;
  if (udp_socket == INVALID_SOCKET) {
    fprintf(stderr, "UDP Thread: Failed to create socket.\n");
    _endthreadex(1);
    return 1;
  }

  char recv_buffer[65536]; // 足够大的缓冲区
  sockaddr_in sender_addr;
  int sender_addr_len = sizeof(sender_addr);
  int bytes_received;

  while (g_running) {
    // 使用 select 或直接 recvfrom 带超时
    // 这里使用带超时的 recvfrom 模拟非阻塞或定期检查 g_running
    // 更好的方式是使用 select 或 WSAEventSelect，但为简化使用超时
    // 注意: Windows 下 recvfrom 的阻塞行为

    // 设置接收超时为 100ms，以便能定期检查 g_running
    DWORD timeout = 100; // 100ms
    setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
               sizeof(timeout));

    bytes_received = recvfrom(udp_socket, recv_buffer, sizeof(recv_buffer), 0,
                              (sockaddr *)&sender_addr, &sender_addr_len);

    if (bytes_received == SOCKET_ERROR) {
      int error = WSAGetLastError();
      if (error != WSAETIMEDOUT) { // 忽略超时，用于循环检查
        // fprintf(stderr, "UDP Thread: recvfrom error: %d\n", error);
      }
      continue; // 继续循环
    }

    // 检查来源 IP 和端口 (可选安全检查)
    char sender_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip_str, INET_ADDRSTRLEN);
    if (strcmp(sender_ip_str, UDP_FORWARD_IP) != 0 ||
        ntohs(sender_addr.sin_port) != UDP_FORWARD_PORT) {
      printf("UDP Thread: Ignoring packet from %s:%d (expected %s:%d)\n",
             sender_ip_str, ntohs(sender_addr.sin_port), UDP_FORWARD_IP,
             UDP_FORWARD_PORT);
      continue;
    }

    // printf("UDP Thread: Received %d bytes from %s:%d\n", bytes_received,
    // sender_ip_str, ntohs(sender_addr.sin_port));

    // 使用无锁队列优化，将收到的数据包放入队列中，由专门的线程处理发送
    if (g_udp_packet_queue) {
      // 使用零拷贝方法创建PacketData对象并入队
      auto packet_data = PacketData::create_shared((const uint8_t *)recv_buffer,
                                                   bytes_received);
      g_udp_packet_queue->enqueue_shared(std::move(packet_data));
    }
  }

  closesocket(udp_socket);
  printf("UDP Thread: Exiting.\n");
  _endthreadex(0);
  return 0;
}
// --- 功能 2 结束 ---

int wintun_init(const WCHAR *adapter_name, const WCHAR *tunnel_name,
                const WCHAR *ip_str, int netmask_cidr) {
  if (!adapter_name || !tunnel_name || !ip_str)
    return -1;

  // 创建或打开适配器
  g_tun_adpter = WintunCreateAdapter(adapter_name, tunnel_name, NULL);
  if (!g_tun_adpter) {
    fprintf(stderr, "[-] WintunCreateAdapter failed: %lu\n", GetLastError());
    goto fail;
  }

  // 创建session
  g_session = WintunStartSession(g_tun_adpter, 0x80000);

  printf("[+] Wintun initialized: %s (%s)\n", adapter_name, tunnel_name);

  // 提示用户配置 IP（或使用 netsh / AddIPAddress）
  if (netmask_cidr >= 0) {
    printf("[*] Please assign IP %s/%d manually via netsh or control panel.\n",
           ip_str, netmask_cidr);
  }

  if (false == enable_interface_forwarding(adapter_name)) {
    goto fail;
  }

  return 0;

fail:
  wintun_shutdown();
  return -1;
}

int wintun_send(const uint8_t *packet, size_t len) {
  if (!g_session || !packet || len == 0 || len > WINTUN_MAX_IP_PACKET_SIZE) {
    fprintf(stderr, "[-] Invalid parameter or session not ready\n");
    return -1;
  }

  BYTE *frame = WintunAllocateSendPacket(g_session, (DWORD)len);
  if (!frame) {
    fprintf(stderr, "[-] WintunAllocateSendPacket failed: %lu\n",
            GetLastError());
    return -1;
  }

  memcpy(frame, packet, len);

  WintunSendPacket(g_session, frame);
  return 0;
}

void wintun_shutdown(void) {
  if (g_session) {
    WintunEndSession(g_session);
    g_session = NULL;
  }

  if (g_tun_adpter) {
    WintunCloseAdapter(g_tun_adpter);
    g_tun_adpter = NULL;
  }
}

static HMODULE InitializeWintun(void) {
  HMODULE Wintun = LoadLibraryExW(L"wintun.dll", NULL,
                                  LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                      LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!Wintun)
    return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
  if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) ||
      X(WintunGetAdapterLUID) || X(WintunGetRunningDriverVersion) ||
      X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
      X(WintunEndSession) || X(WintunGetReadWaitEvent) ||
      X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
      X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
  {
    DWORD LastError = GetLastError();
    FreeLibrary(Wintun);
    SetLastError(LastError);
    return NULL;
  }
  return Wintun;
}

BOOL enable_interface_forwarding(const WCHAR *adapter_name) {
  PMIB_IF_TABLE2 pIfTable;
  DWORD status = GetIfTable2(&pIfTable);
  if (status != NO_ERROR) {
    fprintf(stderr, "[-] GetIfTable2 failed: %lu\n", status);
    return FALSE;
  }

  BOOL found = FALSE;
  for (ULONG i = 0; i < pIfTable->NumEntries; i++) {
    PMIB_IF_ROW2 row = &pIfTable->Table[i];

    // 匹配接口别名（即适配器显示名称）
    if (wcscmp(row->Alias, adapter_name) == 0) {
      MIB_IPINTERFACE_ROW ipRow = {0};
      ipRow.Family = AF_INET;
      ipRow.InterfaceLuid = row->InterfaceLuid;
      // ipRow.InterfaceIndex = row->InterfaceIndex; // 也可使用 Index

      // 获取当前 IP 接口状态
      status = GetIpInterfaceEntry(&ipRow);
      if (status != NO_ERROR) {
        fprintf(stderr, "[-] GetIpInterfaceEntry failed: %lu\n", status);
        continue;
      }

      ipRow.ForwardingEnabled = true;
      ipRow.SitePrefixLength = 0;

      status = SetIpInterfaceEntry(&ipRow);
      if (status != NO_ERROR) {
        fprintf(stderr,
                "[-] SetIpInterfaceEntry failed to enable forwarding: %lu\n",
                status);
        FreeMibTable(pIfTable);
        return FALSE;
      }

      printf("[+] Per-interface forwarding enabled for '%ls' (LUID: %016llX)\n",
             adapter_name, row->InterfaceLuid.Value);
      found = TRUE;
      break;
    }
  }

  FreeMibTable(pIfTable);

  if (!found) {
    fprintf(stderr, "[-] Interface with alias '%ls' not found.\n",
            adapter_name);
    return FALSE;
  }

  return TRUE;
}
