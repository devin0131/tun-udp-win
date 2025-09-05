#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <stack>
#include <mutex>
#include <windows.h>

// 优化的无锁队列节点结构
template <typename T>
struct LockFreeNode {
    std::shared_ptr<T> data;
    std::atomic<LockFreeNode<T>*> next;

    LockFreeNode() : next(nullptr) {}
};

// 无锁队列实现 - 修复版本（基于 Michael & Scott 算法）
template <typename T>
class LockFreeQueue {
private:
    alignas(64) std::atomic<LockFreeNode<T>*> head;
    alignas(64) std::atomic<LockFreeNode<T>*> tail;

    // 对象池（用互斥锁保护，避免复杂无锁栈）
    mutable std::mutex pool_mutex;
    mutable std::stack<LockFreeNode<T>*> node_pool;
    mutable std::atomic<size_t> pool_size;
    static constexpr size_t MAX_POOL_SIZE = 1000;

    // 事件对象，用于通知队列中有新元素
    HANDLE queue_event;

    // 获取节点（从池或 new）
    LockFreeNode<T>* acquire_node() {
        std::lock_guard<std::mutex> lock(pool_mutex);
        if (!node_pool.empty() && pool_size.load(std::memory_order_relaxed) > 0) {
            LockFreeNode<T>* node = node_pool.top();
            node_pool.pop();
            pool_size.fetch_sub(1, std::memory_order_relaxed);
            node->next.store(nullptr, std::memory_order_relaxed);
            return node;
        }
        return new LockFreeNode<T>();
    }

    // 回收节点到池
    void release_node(LockFreeNode<T>* node) {
        if (!node) return;

        // 清理节点数据
        node->data.reset();

        std::lock_guard<std::mutex> lock(pool_mutex);
        if (pool_size.load(std::memory_order_relaxed) < MAX_POOL_SIZE) {
            node_pool.push(node);
            pool_size.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            delete node;
        }
    }
    
public:
    // 获取当前池大小
    size_t get_pool_size() const {
        return pool_size.load(std::memory_order_relaxed);
    }
    
    // 获取池中节点数量
    size_t get_node_count() const {
        std::lock_guard<std::mutex> lock(pool_mutex);
        return node_pool.size();
    }

public:
    LockFreeQueue() : pool_size(0) {
        LockFreeNode<T>* dummy = new LockFreeNode<T>();  // dummy node
        head.store(dummy, std::memory_order_relaxed);
        tail.store(dummy, std::memory_order_relaxed);
        
        // 创建手动重置事件，初始状态为无信号
        queue_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    }

    ~LockFreeQueue() {
        // 仅当无并发访问时调用
        LockFreeNode<T>* curr = head.load(std::memory_order_relaxed);
        while (curr) {
            LockFreeNode<T>* next = curr->next.load(std::memory_order_relaxed);
            // 清理节点数据
            curr->data.reset();
            delete curr;
            curr = next;
        }

        // 清理对象池
        std::lock_guard<std::mutex> lock(pool_mutex);
        while (!node_pool.empty()) {
            LockFreeNode<T>* node = node_pool.top();
            node->data.reset();
            delete node;
            node_pool.pop();
        }
        
        // 关闭事件对象
        if (queue_event != NULL && queue_event != INVALID_HANDLE_VALUE) {
            CloseHandle(queue_event);
        }
    }

    // 入队 - 使用 CAS
    void enqueue(const T& item) {
        LockFreeNode<T>* node = acquire_node();
        node->data = std::make_shared<T>(item);

        std::atomic_thread_fence(std::memory_order_release); // 确保 data 初始化完成

        LockFreeNode<T>* prev = tail.load(std::memory_order_relaxed);
        while (true) {
            LockFreeNode<T>* next = prev->next.load(std::memory_order_acquire);
            if (prev == tail.load(std::memory_order_relaxed)) {
                if (next == nullptr) {
                    // 尝试链接新节点
                    if (prev->next.compare_exchange_weak(next, node, std::memory_order_acq_rel)) {
                        // 成功，更新 tail
                        tail.compare_exchange_weak(prev, node, std::memory_order_acq_rel);
                        // 设置事件以通知等待的线程
                        SetEvent(queue_event);
                        return;
                    }
                }
                else {
                    // tail 滞后，推进 tail
                    tail.compare_exchange_weak(prev, next, std::memory_order_acq_rel);
                }
            }
            else {
                // tail 已被其他线程更新，重试
                prev = tail.load(std::memory_order_relaxed);
            }
        }
    }

    void enqueue(T&& item) {
        LockFreeNode<T>* node = acquire_node();
        node->data = std::make_shared<T>(std::move(item));

        std::atomic_thread_fence(std::memory_order_release);

        LockFreeNode<T>* prev = tail.load(std::memory_order_relaxed);
        while (true) {
            LockFreeNode<T>* next = prev->next.load(std::memory_order_acquire);
            if (prev == tail.load(std::memory_order_relaxed)) {
                if (next == nullptr) {
                    if (prev->next.compare_exchange_weak(next, node, std::memory_order_acq_rel)) {
                        tail.compare_exchange_weak(prev, node, std::memory_order_acq_rel);
                        // 设置事件以通知等待的线程
                        SetEvent(queue_event);
                        return;
                    }
                }
                else {
                    tail.compare_exchange_weak(prev, next, std::memory_order_acq_rel);
                }
            }
            else {
                prev = tail.load(std::memory_order_relaxed);
            }
        }
    }

    // 零拷贝入队 - 直接使用已有的shared_ptr
    void enqueue_shared(std::shared_ptr<T>&& item) {
        LockFreeNode<T>* node = acquire_node();
        node->data = std::move(item);

        std::atomic_thread_fence(std::memory_order_release);

        LockFreeNode<T>* prev = tail.load(std::memory_order_relaxed);
        while (true) {
            LockFreeNode<T>* next = prev->next.load(std::memory_order_acquire);
            if (prev == tail.load(std::memory_order_relaxed)) {
                if (next == nullptr) {
                    if (prev->next.compare_exchange_weak(next, node, std::memory_order_acq_rel)) {
                        tail.compare_exchange_weak(prev, node, std::memory_order_acq_rel);
                        // 设置事件以通知等待的线程
                        SetEvent(queue_event);
                        return;
                    }
                }
                else {
                    tail.compare_exchange_weak(prev, next, std::memory_order_acq_rel);
                }
            }
            else {
                prev = tail.load(std::memory_order_relaxed);
            }
        }
    }
    
    // 零拷贝入队 - 使用已有的shared_ptr（左值引用版本）
    void enqueue_shared(const std::shared_ptr<T>& item) {
        LockFreeNode<T>* node = acquire_node();
        node->data = item;

        std::atomic_thread_fence(std::memory_order_release);

        LockFreeNode<T>* prev = tail.load(std::memory_order_relaxed);
        while (true) {
            LockFreeNode<T>* next = prev->next.load(std::memory_order_acquire);
            if (prev == tail.load(std::memory_order_relaxed)) {
                if (next == nullptr) {
                    if (prev->next.compare_exchange_weak(next, node, std::memory_order_acq_rel)) {
                        tail.compare_exchange_weak(prev, node, std::memory_order_acq_rel);
                        // 设置事件以通知等待的线程
                        SetEvent(queue_event);
                        return;
                    }
                }
                else {
                    tail.compare_exchange_weak(prev, next, std::memory_order_acq_rel);
                }
            }
            else {
                prev = tail.load(std::memory_order_relaxed);
            }
        }
    }
    
    // 高效入队 - 直接使用T对象构建shared_ptr
    void enqueue_direct(T&& item) {
        LockFreeNode<T>* node = acquire_node();
        node->data = std::make_shared<T>(std::move(item));

        std::atomic_thread_fence(std::memory_order_release);

        LockFreeNode<T>* prev = tail.load(std::memory_order_relaxed);
        while (true) {
            LockFreeNode<T>* next = prev->next.load(std::memory_order_acquire);
            if (prev == tail.load(std::memory_order_relaxed)) {
                if (next == nullptr) {
                    if (prev->next.compare_exchange_weak(next, node, std::memory_order_acq_rel)) {
                        tail.compare_exchange_weak(prev, node, std::memory_order_acq_rel);
                        // 设置事件以通知等待的线程
                        SetEvent(queue_event);
                        return;
                    }
                }
                else {
                    tail.compare_exchange_weak(prev, next, std::memory_order_acq_rel);
                }
            }
            else {
                prev = tail.load(std::memory_order_relaxed);
            }
        }
    }

    // 出队 - 直接返回shared_ptr以避免栈上分配
    std::shared_ptr<T> dequeue() {
        LockFreeNode<T>* old_head = head.load(std::memory_order_relaxed);
        while (true) {
            LockFreeNode<T>* first = old_head->next.load(std::memory_order_acquire);
            if (first == nullptr) {
                return nullptr; // 队列为空
            }

            // 尝试移动 head
            if (head.compare_exchange_weak(old_head, first, std::memory_order_acq_rel)) {
                // 成功出队
                std::shared_ptr<T> item = std::move(first->data);
                release_node(old_head); // 释放旧 head（dummy 或前节点）
                
                // 检查队列是否为空，如果为空则重置事件
                if (first->next.load(std::memory_order_acquire) == nullptr) {
                    ResetEvent(queue_event);
                }
                
                return item;
            }
            // CAS 失败，重试
        }
    }
    
    // 带超时的出队函数
    std::shared_ptr<T> dequeue_with_timeout(DWORD timeout_ms) {
        // 首先尝试无等待出队
        auto item = dequeue();
        if (item) {
            return item;
        }
        
        // 如果队列为空，等待事件或超时
        if (WaitForSingleObject(queue_event, timeout_ms) == WAIT_OBJECT_0) {
            // 事件被触发，再次尝试出队
            return dequeue();
        }
        
        // 超时或出错
        return nullptr;
    }
    
    // 阻塞式出队函数
    std::shared_ptr<T> dequeue_blocking() {
        // 首先尝试无等待出队
        auto item = dequeue();
        if (item) {
            return item;
        }
        
        // 如果队列为空，等待事件
        WaitForSingleObject(queue_event, INFINITE);
        
        // 事件被触发，再次尝试出队
        return dequeue();
    }

    // 兼容的出队方法 - 保留原来的接口以保证向后兼容
    bool dequeue(T& item) {
        auto ptr = dequeue();
        if (ptr) {
            item = std::move(*ptr);
            return true;
        }
        return false;
    }

    bool empty() const {
        LockFreeNode<T>* h = head.load(std::memory_order_relaxed);
        LockFreeNode<T>* next = h->next.load(std::memory_order_acquire);
        return next == nullptr;
    }
};