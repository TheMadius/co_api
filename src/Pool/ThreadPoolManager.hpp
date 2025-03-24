#pragma once

#include "singleton.hpp"
#include "concurrencpp/concurrencpp.h"
#include <unordered_map>
#include <co_async/co_async.hpp>
#include <co_async/std.hpp>

namespace pool
{

class ThreadPoolManager : public ov::Singleton<ThreadPoolManager>
{
  public:
    friend class ov::Singleton<ThreadPoolManager>;

    void Init(uint32_t thread_count = 0);

    std::shared_ptr<concurrencpp::thread_pool_executor> getThreadPool();

    std::shared_ptr<concurrencpp::thread_pool_executor> getBackgroundThreadPool();

    concurrencpp::lazy_result<void> makeDelayObject(uint64_t daley_ms, bool background = true);

    concurrencpp::result<void> toBackgroundThreadPool();

    concurrencpp::result<void> toThreadPool();

    void DeleteTimer(const std::string &name);

    template <class callable_type, class... argument_types>
    void AddTimer(const std::string &name, std::chrono::milliseconds first_delay, std::chrono::milliseconds freq,
                  callable_type &&callable, argument_types &&...arguments)
    {
        std::scoped_lock lk(_timers_mtx);

        if (_timers.contains(name))
            throw std::runtime_error("Timer '" + name + "' is already exist!");

        _timers[name] = runtime->timer_queue()->make_timer(first_delay, freq, runtime->thread_pool_executor(),
                                                           std::forward<callable_type>(callable),
                                                           std::forward<argument_types>(arguments)...);
    }

    ~ThreadPoolManager() = default;

    void stopRuntime();

  private:
    std::unordered_map<std::string, concurrencpp::timer> _timers;

    std::unordered_map<std::thread::id, co_async::IOContext> _io_ctx;

    std::unique_ptr<concurrencpp::runtime> runtime;

    ThreadPoolManager() = default;

    std::mutex _timers_mtx;

    std::mutex _io_mtx;
};
} // namespace pool