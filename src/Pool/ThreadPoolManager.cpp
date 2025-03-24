#include "ThreadPoolManager.hpp"
#include <co_async/generic/generic_io.hpp>
#include <iostream>
#include <mutex>
#include <thread>
namespace pool
{

void ThreadPoolManager::stopRuntime()
{
    for (auto &[name, timer] : _timers)
    {
        timer.cancel();
    }
    _timers.clear();
    if (runtime != nullptr)
    {
        runtime->timer_queue()->shutdown();
        runtime->background_executor()->shutdown();
        runtime->thread_pool_executor()->shutdown();
        runtime.reset();
        runtime = nullptr;
    }
};

void ThreadPoolManager::Init(uint32_t thread_count)
{
    if (thread_count == 0)
    {
        thread_count = std::thread::hardware_concurrency();
    }
    concurrencpp::runtime_options runtimeOptions;
    static std::atomic_uint64_t count_thread = 0;
    runtimeOptions.thread_started_callback = [this](std::string_view str) 
    {
        // _io_ctx[std::this_thread::get_id()];
    };
    runtimeOptions.thread_terminated_callback = [this](std::string_view str) 
    {
        // _io_ctx.erase(std::this_thread::get_id());
    };
    runtimeOptions.max_cpu_threads = thread_count;
    runtimeOptions.max_background_threads =
        concurrencpp::details::consts::k_background_threadpool_worker_count_factor * thread_count;
    runtime = std::make_unique<concurrencpp::runtime>(runtimeOptions);
}

std::shared_ptr<concurrencpp::thread_pool_executor> ThreadPoolManager::getThreadPool()
{
    if (runtime)
        return runtime->thread_pool_executor();
    return nullptr;
}

std::shared_ptr<concurrencpp::thread_pool_executor> ThreadPoolManager::getBackgroundThreadPool()
{
    if (runtime)
        return runtime->background_executor();
    return nullptr;
}

concurrencpp::lazy_result<void> ThreadPoolManager::makeDelayObject(uint64_t daley_ms, bool background)
{
    if (runtime)
    {
        if (background)
            return runtime->timer_queue()->make_delay_object(std::chrono::milliseconds(daley_ms),
                                                             runtime->background_executor());
        else
            return runtime->timer_queue()->make_delay_object(std::chrono::milliseconds(daley_ms),
                                                             runtime->thread_pool_executor());
    }
    throw std::runtime_error("Not Start Pool");
}

concurrencpp::result<void> ThreadPoolManager::toThreadPool()
{
    if (runtime)
    {
        co_await concurrencpp::resume_on(runtime->thread_pool_executor());
        co_return;
    }
    throw std::runtime_error("Not Start Pool");
}

void ThreadPoolManager::DeleteTimer(const std::string &name)
{
    std::scoped_lock lk(_timers_mtx);

    if (!_timers.contains(name))
        return;

    _timers[name].cancel();
    _timers.erase(name);
}

concurrencpp::result<void> ThreadPoolManager::toBackgroundThreadPool()
{
    if (runtime)
    {
        co_await concurrencpp::resume_on(runtime->background_executor());
        co_return;
    }
    throw std::runtime_error("Not Start Pool");
}
} // namespace pool
