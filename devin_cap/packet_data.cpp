#include "packet_data.h"
#include <cstdio>

// 静态成员定义
std::atomic<PacketDataPool::Node*> PacketDataPool::head(nullptr);
std::atomic<size_t> PacketDataPool::pool_size(0);
std::atomic<size_t> PacketDataPool::alloc_count(0);
std::atomic<size_t> PacketDataPool::reuse_count(0);

// PacketDataPool的实现
std::shared_ptr<PacketData> PacketDataPool::acquire() {
    // 尝试从池中获取一个PacketData对象
    Node* current_head = head.load(std::memory_order_acquire);
    while (current_head && pool_size.load(std::memory_order_relaxed) > 0) {
        // 尝试CAS操作，将头节点替换为下一个节点
        Node* next = current_head->next.load(std::memory_order_acquire);
        if (head.compare_exchange_weak(current_head, next,
                                       std::memory_order_release,
                                       std::memory_order_acquire)) {
            // CAS成功，获取到了一个节点
            pool_size.fetch_sub(1, std::memory_order_relaxed);

            // 获取packet并重置状态
            auto packet = std::move(current_head->packet);
            if (packet) {
                packet->data.clear();
            }

            // 释放节点内存
            delete current_head;

            reuse_count.fetch_add(1, std::memory_order_relaxed);
            return packet;
        }
        // CAS失败，重新尝试
    }

    // 池为空，创建新对象
    alloc_count.fetch_add(1, std::memory_order_relaxed);
    return std::make_shared<PacketData>();
}

void PacketDataPool::release(std::shared_ptr<PacketData> packet) {
    if (!packet)
        return;

    // 检查池是否已满
    if (pool_size.load(std::memory_order_relaxed) >= MAX_POOL_SIZE) {
        // 池已满，直接返回，让shared_ptr自动释放内存
        return;
    }

    // 重置对象状态
    packet->data.clear();

    // 创建新节点并添加到池中
    Node* new_node = new Node(std::move(packet));
    Node* current_head = head.load(std::memory_order_acquire);

    do {
        // 设置新节点的next指针
        new_node->next.store(current_head, std::memory_order_release);
        // 尝试CAS操作，将新节点设置为头节点
    } while (!head.compare_exchange_weak(current_head, new_node,
                                         std::memory_order_release,
                                         std::memory_order_acquire));

    pool_size.fetch_add(1, std::memory_order_relaxed);
}

// 获取当前池大小
size_t PacketDataPool::get_pool_size() {
    return pool_size.load(std::memory_order_relaxed);
}

// 获取统计信息
size_t PacketDataPool::get_alloc_count() {
    return alloc_count.load(std::memory_order_relaxed);
}

size_t PacketDataPool::get_reuse_count() {
    return reuse_count.load(std::memory_order_relaxed);
}

// 打印统计信息
void PacketDataPool::print_stats() {
    size_t alloc = alloc_count.load(std::memory_order_relaxed);
    size_t reuse = reuse_count.load(std::memory_order_relaxed);
    size_t pool = pool_size.load(std::memory_order_relaxed);

    printf("PacketDataPool Stats - Allocated: %zu, Reused: %zu, Pool Size: %zu\n",
           alloc, reuse, pool);
}

// PacketData的实现
PacketData::PacketData() {}

PacketData::PacketData(size_t size) : data(size) {}

PacketData::PacketData(const uint8_t* packet_data, int packet_len) {
    data.assign(packet_data, packet_len);
}

// 从已有的PacketBuffer创建PacketData
PacketData::PacketData(const PacketBuffer& packet_data) : data(packet_data) {}

// 移动构造函数
PacketData::PacketData(PacketData&& other) noexcept 
    : data(std::move(other.data)) {
}

// 移动赋值操作符
PacketData& PacketData::operator=(PacketData&& other) noexcept {
    if (this != &other) {
        data = std::move(other.data);
    }
    return *this;
}

#include <chrono>
#include <iostream>
#include <iomanip>

// 获取高精度时间戳的辅助函数
inline std::string getHighResTimestamp() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
    auto seconds = microseconds / 1000000;
    auto usecs = microseconds % 1000000;
    
    // 获取当前时间的时分秒
    std::time_t t = std::time(nullptr);
    std::tm tm;
    localtime_s(&tm, &t);
    
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << tm.tm_hour << ":"
        << std::setfill('0') << std::setw(2) << tm.tm_min << ":"
        << std::setfill('0') << std::setw(2) << tm.tm_sec << "."
        << std::setfill('0') << std::setw(6) << usecs;
    return oss.str();
}

// 零拷贝工厂方法 - 从现有数据创建shared_ptr（使用内存池）
std::shared_ptr<PacketData> PacketData::create_shared(const uint8_t* packet_data, int packet_len) {
    // 记录开始时间
    auto start_time = std::chrono::high_resolution_clock::now();
    std::cout << "[CREATE_SHARED START] Timestamp: " << getHighResTimestamp() << std::endl;
    
    auto packet = PacketDataPool::acquire();
    packet->data.assign(packet_data, packet_len);
    
    // 记录结束时间并计算耗时
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
    std::cout << "[CREATE_SHARED END] Timestamp: " << getHighResTimestamp() 
              << " Duration: " << duration << " microseconds" << std::endl;
    
    return packet;
}

// 零拷贝工厂方法 - 从已有的PacketBuffer创建shared_ptr（使用内存池）
std::shared_ptr<PacketData> PacketData::create_shared(const PacketBuffer& packet_data) {
    // 记录开始时间
    auto start_time = std::chrono::high_resolution_clock::now();
    std::cout << "[CREATE_SHARED START] Timestamp: " << getHighResTimestamp() << std::endl;
    
    auto packet = PacketDataPool::acquire();
    packet->data = packet_data;
    
    // 记录结束时间并计算耗时
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
    std::cout << "[CREATE_SHARED END] Timestamp: " << getHighResTimestamp() 
              << " Duration: " << duration << " microseconds" << std::endl;
    
    return packet;
}

// 拷贝构造函数
PacketData::PacketData(const PacketData& other) 
    : data(other.data) {}

// 拷贝赋值操作符
PacketData& PacketData::operator=(const PacketData& other) {
    if (this != &other) {
        data = other.data;
    }
    return *this;
}

// 获取数据长度
size_t PacketData::size() const { 
    return data.size(); 
}

// 析构时将对象返回到内存池
PacketData::~PacketData() {
    // 注意：不能在这里直接调用PacketDataPool::release，
    // 因为shared_ptr可能仍被其他地方引用
}