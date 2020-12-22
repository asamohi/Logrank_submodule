//
// Created by Anat Samohi on 23/10/2020.
//

#ifndef SEAL_SEMAPHORE_H
#define SEAL_SEMAPHORE_H

#include <condition_variable>
#include <exception>
#include <mutex>
#include "../../../examples.h"
#include "serv_func.h"

class Semaphore
{
private:
    std::mutex mutex_;
    std::condition_variable condition_;
    unsigned long count_ = 0; // Initialized as locked.

public:
    void notify() {
        std::lock_guard<decltype(mutex_)> lock(mutex_);
        ++count_;
        condition_.notify_one();
    }

    void wait() {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        while(!count_) // Handle spurious wake-ups.
            condition_.wait(lock);
        --count_;
    }

    bool try_wait() {
        std::lock_guard<decltype(mutex_)> lock(mutex_);
        if(count_) {
            --count_;
            return true;
        }
        return false;
    }
};

class BinarySemaphore
{
private:
    std::mutex mutex_;
    std::condition_variable condition_;
    unsigned long count_ = 0; // Initialized as locked.

public:
    void notify() {
        std::lock_guard<decltype(mutex_)> lock(mutex_);
        if (count_ > 0)
        {
            print_line(__LINE__);
            cout << "Error: Binary_semaphore.notify was called from "<< typeid(this).name() <<
                " but the count_ is " << count_ << endl;
        }
        ++count_;
        condition_.notify_one();
    }

    void wait() {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        while(!count_) // Handle spurious wake-ups.
            condition_.wait(lock);
        --count_;
    }

    bool try_wait() {
        std::lock_guard<decltype(mutex_)> lock(mutex_);
        if(count_) {
            --count_;
            return true;
        }
        return false;
    }
};


#endif // SEAL_SEMAPHORE_H
