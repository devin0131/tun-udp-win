#ifndef PACKET_DATA_H
#define PACKET_DATA_H

#include <memory>
#include <atomic>
#include "packet_buffer.h"

// 前向声明
struct PacketData;

// 无锁的PacketData池实现
class PacketDataPool {
private:
    static constexpr size_t MAX_POOL_SIZE = 1000;

    // 使用链表实现无锁栈
    struct Node {
        std::shared_ptr<PacketData> packet;
        std::atomic<Node*> next;

        Node() : next(nullptr) {}
        Node(std::shared_ptr<PacketData> p) : packet(std::move(p)), next(nullptr) {}
    };

    // 头节点指针
    static std::atomic<Node*> head;

    // 池大小计数器
    static std::atomic<size_t> pool_size;

    // 统计信息
    static std::atomic<size_t> alloc_count;
    static std::atomic<size_t> reuse_count;

public:
    static std::shared_ptr<PacketData> acquire();
    static void release(std::shared_ptr<PacketData> packet);

    // 获取当前池大小
    static size_t get_pool_size();

    // 获取统计信息
    static size_t get_alloc_count();
    static size_t get_reuse_count();

    // 打印统计信息
    static void print_stats();
};

// 数据包结构体定义
struct PacketData : public std::enable_shared_from_this<PacketData> {
    PacketBuffer data;

    PacketData();
    PacketData(size_t size);  // 添加构造函数
    PacketData(const uint8_t* packet_data, int packet_len);
    
    // 从已有的PacketBuffer创建PacketData
    PacketData(const PacketBuffer& packet_data);

    // 移动构造函数
    PacketData(PacketData&& other) noexcept;
    
    // 移动赋值操作符
    PacketData& operator=(PacketData&& other) noexcept;

    // 零拷贝工厂方法 - 从现有数据创建shared_ptr（使用内存池）
    static std::shared_ptr<PacketData> create_shared(const uint8_t* packet_data, int packet_len);

    // 零拷贝工厂方法 - 从已有的PacketBuffer创建shared_ptr（使用内存池）
    static std::shared_ptr<PacketData> create_shared(const PacketBuffer& packet_data);

    // 拷贝构造函数
    PacketData(const PacketData& other);

    // 拷贝赋值操作符
    PacketData& operator=(const PacketData& other);

    // 获取数据长度
    size_t size() const;

    // 析构时将对象返回到内存池
    ~PacketData();
};

#endif // PACKET_DATA_H