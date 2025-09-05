#pragma once

#include <atomic>
#include <memory>
#include <cstdint>

// 无锁节点结构
template <typename T>
struct LockFreePoolNode {
    T data;
    std::atomic<LockFreePoolNode<T>*> next;

    LockFreePoolNode() : next(nullptr) {}
    LockFreePoolNode(T&& item) : data(std::move(item)), next(nullptr) {}
    LockFreePoolNode(const T& item) : data(item), next(nullptr) {}
};

// 无锁对象池实现 - 通用版本
template <typename T>
class LockFreePool {
private:
    static constexpr size_t MAX_POOL_SIZE = 1000;
    
    // 使用原子指针作为栈顶
    alignas(64) std::atomic<LockFreePoolNode<T>*> pool_top;
    
    // 当前池大小
    alignas(64) std::atomic<size_t> pool_size;
    
    // 统计信息
    alignas(64) std::atomic<size_t> alloc_count;
    alignas(64) std::atomic<size_t> reuse_count;

public:
    LockFreePool() : pool_top(nullptr), pool_size(0), alloc_count(0), reuse_count(0) {}
    
    ~LockFreePool() {
        // 清理池中的所有节点
        LockFreePoolNode<T>* current = pool_top.load(std::memory_order_relaxed);
        while (current) {
            LockFreePoolNode<T>* next = current->next.load(std::memory_order_relaxed);
            delete current;
            current = next;
        }
    }
    
    // 获取对象（从池或创建新对象）
    T acquire() {
        LockFreePoolNode<T>* node = nullptr;
        
        // 尝试从池中获取节点
        LockFreePoolNode<T>* current_top = pool_top.load(std::memory_order_acquire);
        while (current_top && pool_size.load(std::memory_order_relaxed) > 0) {
            // 尝试弹出节点
            LockFreePoolNode<T>* next = current_top->next.load(std::memory_order_acquire);
            if (pool_top.compare_exchange_weak(current_top, next, std::memory_order_acq_rel)) {
                // 成功弹出节点
                pool_size.fetch_sub(1, std::memory_order_relaxed);
                node = current_top;
                reuse_count.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            // CAS失败，重试
            current_top = pool_top.load(std::memory_order_acquire);
        }
        
        if (node) {
            // 从池中获取到节点，返回其中的数据
            T result = std::move(node->data);
            delete node;
            return result;
        }
        
        // 池为空，创建新对象
        alloc_count.fetch_add(1, std::memory_order_relaxed);
        return T();
    }
    
    // 回收对象到池
    void release(T&& item) {
        // 检查池是否已满
        if (pool_size.load(std::memory_order_relaxed) >= MAX_POOL_SIZE) {
            // 池已满，直接丢弃对象让其自动析构
            return;
        }
        
        // 创建新节点
        LockFreePoolNode<T>* node = new LockFreePoolNode<T>(std::move(item));
        
        // 将节点压入栈
        LockFreePoolNode<T>* current_top = pool_top.load(std::memory_order_acquire);
        do {
            node->next.store(current_top, std::memory_order_release);
        } while (!pool_top.compare_exchange_weak(current_top, node, std::memory_order_acq_rel));
        
        pool_size.fetch_add(1, std::memory_order_relaxed);
    }
    
    // 获取当前池大小
    size_t get_pool_size() const {
        return pool_size.load(std::memory_order_relaxed);
    }
    
    // 获取分配统计
    size_t get_alloc_count() const {
        return alloc_count.load(std::memory_order_relaxed);
    }
    
    // 获取重用统计
    size_t get_reuse_count() const {
        return reuse_count.load(std::memory_order_relaxed);
    }
};

// 无锁对象池实现 - 指针特化版本
template <typename T>
class LockFreePool<T*> {
private:
    static constexpr size_t MAX_POOL_SIZE = 1000;
    
    // 使用原子指针作为栈顶
    alignas(64) std::atomic<LockFreePoolNode<T*>*> pool_top;
    
    // 当前池大小
    alignas(64) std::atomic<size_t> pool_size;
    
    // 统计信息
    alignas(64) std::atomic<size_t> alloc_count;
    alignas(64) std::atomic<size_t> reuse_count;

public:
    LockFreePool() : pool_top(nullptr), pool_size(0), alloc_count(0), reuse_count(0) {}
    
    ~LockFreePool() {
        // 清理池中的所有节点
        LockFreePoolNode<T*>* current = pool_top.load(std::memory_order_relaxed);
        while (current) {
            LockFreePoolNode<T*>* next = current->next.load(std::memory_order_relaxed);
            delete current->data;  // 删除指针指向的对象
            delete current;        // 删除节点
            current = next;
        }
    }
    
    // 获取对象（从池或创建新对象）
    T* acquire() {
        LockFreePoolNode<T*>* node = nullptr;
        
        // 尝试从池中获取节点
        LockFreePoolNode<T*>* current_top = pool_top.load(std::memory_order_acquire);
        while (current_top && pool_size.load(std::memory_order_relaxed) > 0) {
            // 尝试弹出节点
            LockFreePoolNode<T*>* next = current_top->next.load(std::memory_order_acquire);
            if (pool_top.compare_exchange_weak(current_top, next, std::memory_order_acq_rel)) {
                // 成功弹出节点
                pool_size.fetch_sub(1, std::memory_order_relaxed);
                node = current_top;
                reuse_count.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            // CAS失败，重试
            current_top = pool_top.load(std::memory_order_acquire);
        }
        
        if (node) {
            // 从池中获取到节点，返回其中的数据
            T* result = node->data;
            delete node;
            return result;
        }
        
        // 池为空，创建新对象
        alloc_count.fetch_add(1, std::memory_order_relaxed);
        return new T();
    }
    
    // 回收对象到池
    void release(T* item) {
        if (!item) return;
        
        // 检查池是否已满
        if (pool_size.load(std::memory_order_relaxed) >= MAX_POOL_SIZE) {
            // 池已满，直接删除对象
            delete item;
            return;
        }
        
        // 创建新节点
        LockFreePoolNode<T*>* node = new LockFreePoolNode<T*>(item);
        
        // 将节点压入栈
        LockFreePoolNode<T*>* current_top = pool_top.load(std::memory_order_acquire);
        do {
            node->next.store(current_top, std::memory_order_release);
        } while (!pool_top.compare_exchange_weak(current_top, node, std::memory_order_acq_rel));
        
        pool_size.fetch_add(1, std::memory_order_relaxed);
    }
    
    // 获取当前池大小
    size_t get_pool_size() const {
        return pool_size.load(std::memory_order_relaxed);
    }
    
    // 获取分配统计
    size_t get_alloc_count() const {
        return alloc_count.load(std::memory_order_relaxed);
    }
    
    // 获取重用统计
    size_t get_reuse_count() const {
        return reuse_count.load(std::memory_order_relaxed);
    }
};