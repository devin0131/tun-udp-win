#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <stack>
#include <mutex>

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
    LockFreeQueue() : pool_size(0) {
        LockFreeNode<T>* dummy = new LockFreeNode<T>();  // dummy node
        head.store(dummy, std::memory_order_relaxed);
        tail.store(dummy, std::memory_order_relaxed);
    }

    ~LockFreeQueue() {
        // 仅当无并发访问时调用
        LockFreeNode<T>* curr = head.load(std::memory_order_relaxed);
        while (curr) {
            LockFreeNode<T>* next = curr->next.load(std::memory_order_relaxed);
            delete curr;
            curr = next;
        }

        // 清理对象池
        std::lock_guard<std::mutex> lock(pool_mutex);
        while (!node_pool.empty()) {
            delete node_pool.top();
            node_pool.pop();
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

    // 出队
    bool dequeue(T& item) {
        LockFreeNode<T>* old_head = head.load(std::memory_order_relaxed);
        while (true) {
            LockFreeNode<T>* first = old_head->next.load(std::memory_order_acquire);
            if (first == nullptr) {
                return false; // 队列为空
            }

            // 尝试移动 head
            if (head.compare_exchange_weak(old_head, first, std::memory_order_acq_rel)) {
                // 成功出队
                item = std::move(*(first->data));
                release_node(old_head); // 释放旧 head（dummy 或前节点）
                return true;
            }
            // CAS 失败，重试
        }
    }

    bool empty() const {
        LockFreeNode<T>* h = head.load(std::memory_order_relaxed);
        LockFreeNode<T>* next = h->next.load(std::memory_order_acquire);
        return next == nullptr;
    }
};