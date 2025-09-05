#pragma once

#include <memory>
#include <cstring>
#include <algorithm>
#include <cstdint>

// 自定义的PacketBuffer结构，用于替代std::vector<uint8_t>管理char[]
struct PacketBuffer {
private:
    std::shared_ptr<uint8_t[]> data_;
    size_t size_;
    size_t capacity_;

public:
    // 构造函数
    PacketBuffer() : size_(0), capacity_(0) {}
    
    // 指定大小的构造函数
    explicit PacketBuffer(size_t size) : size_(size), capacity_(size) {
        if (size > 0) {
            data_ = std::shared_ptr<uint8_t[]>(new uint8_t[size]);
        }
    }
    
    // 从现有数据创建PacketBuffer
    PacketBuffer(const uint8_t* data, size_t size) : size_(size), capacity_(size) {
        if (size > 0) {
            data_ = std::shared_ptr<uint8_t[]>(new uint8_t[size]);
            std::memcpy(data_.get(), data, size);
        }
    }
    
    // 拷贝构造函数
    PacketBuffer(const PacketBuffer& other) 
        : size_(other.size_), capacity_(other.capacity_) {
        if (other.data_ && other.capacity_ > 0) {
            data_ = std::shared_ptr<uint8_t[]>(new uint8_t[other.capacity_]);
            std::memcpy(data_.get(), other.data_.get(), other.size_);
        }
    }
    
    // 拷贝赋值操作符
    PacketBuffer& operator=(const PacketBuffer& other) {
        if (this != &other) {
            size_ = other.size_;
            capacity_ = other.capacity_;
            if (other.data_ && other.capacity_ > 0) {
                data_ = std::shared_ptr<uint8_t[]>(new uint8_t[other.capacity_]);
                std::memcpy(data_.get(), other.data_.get(), other.size_);
            } else {
                data_.reset();
            }
        }
        return *this;
    }
    
    // 移动构造函数
    PacketBuffer(PacketBuffer&& other) noexcept
        : data_(std::move(other.data_)), size_(other.size_), capacity_(other.capacity_) {
        other.size_ = 0;
        other.capacity_ = 0;
    }
    
    // 移动赋值操作符
    PacketBuffer& operator=(PacketBuffer&& other) noexcept {
        if (this != &other) {
            data_ = std::move(other.data_);
            size_ = other.size_;
            capacity_ = other.capacity_;
            other.size_ = 0;
            other.capacity_ = 0;
        }
        return *this;
    }
    
    // 析构函数
    ~PacketBuffer() = default;
    
    // 获取数据指针
    uint8_t* data() { return data_.get(); }
    const uint8_t* data() const { return data_.get(); }
    
    // 获取大小
    size_t size() const { return size_; }
    
    // 获取容量
    size_t capacity() const { return capacity_; }
    
    // 重置大小
    void resize(size_t new_size) {
        if (new_size <= capacity_) {
            size_ = new_size;
        } else {
            // 需要重新分配内存
            auto new_data = std::shared_ptr<uint8_t[]>(new uint8_t[new_size]);
            if (data_) {
                std::memcpy(new_data.get(), data_.get(), size_);
            }
            data_ = std::move(new_data);
            size_ = new_size;
            capacity_ = new_size;
        }
    }
    
    // 分配指定容量（不改变size）
    void reserve(size_t new_capacity) {
        if (new_capacity > capacity_) {
            auto new_data = std::shared_ptr<uint8_t[]>(new uint8_t[new_capacity]);
            if (data_) {
                std::memcpy(new_data.get(), data_.get(), size_);
            }
            data_ = std::move(new_data);
            capacity_ = new_capacity;
        }
    }
    
    // 清空数据
    void clear() {
        size_ = 0;
    }
    
    // 赋值数据
    void assign(const uint8_t* data, size_t size) {
        if (size == 0) {
            size_ = 0;
            return;
        }
        
        // 只有在需要时才调整容量
        if (size > capacity_) {
            // 需要重新分配内存
            auto new_data = std::shared_ptr<uint8_t[]>(new uint8_t[size]);
            data_ = std::move(new_data);
            capacity_ = size;
        }
        
        // 复制数据
        if (data) {
            std::memcpy(data_.get(), data, size);
        }
        size_ = size;
    }
    
    // 追加数据
    void append(const uint8_t* data, size_t size) {
        if (size == 0) return;
        
        size_t new_size = size_ + size;
        if (new_size > capacity_) {
            // 需要扩容，按1.5倍增长策略
            size_t new_capacity = std::max(new_size, capacity_ + capacity_ / 2);
            reserve(new_capacity);
        }
        
        if (data) {
            std::memcpy(data_.get() + size_, data, size);
        }
        size_ = new_size;
    }
};