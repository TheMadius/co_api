
#include <co_async/co_async.hpp>
#include <co_async/std.hpp>

#include "Pool/ThreadPoolManager.hpp"

using namespace co_async;
using namespace std::literals;

struct Worker {
    std::deque<Task<Expected<>>> q;
    std::condition_variable cv;
    std::mutex mtx;
    std::jthread th;

    void spawn(Task<Expected<>> task) {
        std::lock_guard lck(mtx);
        q.push_back(std::move(task));
        cv.notify_all();
    }

    void start(std::size_t i) {
        th = std::jthread([this, i] (std::stop_token stop) {
            IOContext ctx;
            PlatformIOContext::schedSetThreadAffinity(i);
            while (!stop.stop_requested()) [[likely]] {
                while (ctx.runOnce()) {
                    std::lock_guard lck(mtx);
                    if (!q.empty())
                        break;
                }
                std::unique_lock lck(mtx);
                cv.wait(lck, [this] { return !q.empty(); });
                auto task = std::move(q.front());
                q.pop_front();
                lck.unlock();
                co_spawn(std::move(task));
            }
        });
    }
};

std::vector<Worker> workers(std::thread::hardware_concurrency());

Worker &getWorker()
{
    static std::atomic_int64_t i = 0;
    return workers[(i++)%4];
}

Task<Expected<>> responseHTTP(HTTPServer::IO::Ptr io, HTTPResponse res, std::string_view body)
{
    co_await io->response(res, body);
    co_return {};
}

static Task<Expected<>> amain(std::string serveAt) {
    co_await co_await stdio().putline("listening at: "s + serveAt);
    auto listener = co_await co_await listener_bind(co_await AddressResolver().host(serveAt).resolve_one());

    HTTPServer server;
    server.route([](HTTPServer::IO::Ptr &io) -> Task<Expected<>>
    {
        auto _body = co_await co_await io->request_body();
        pool::ThreadPoolManager::GetInstance()->getThreadPool()->submit([io]() -> concurrencpp::result<void>
        {
            HTTPResponse res = {
                .status = 200,
                .headers = {
                    {"content-type", "text/html;charset=utf-8"},
                },
            };
            std::string_view body = "++";
            getWorker().spawn(responseHTTP(io, res, body));
            co_return;
        });
        co_return {};
    });

    for (std::size_t i = 0; i < workers.size(); ++i) {
        workers[i].start(i);
    }

    while (true) {
        if (auto income = co_await listener_accept(listener)) [[likely]] {
            getWorker().spawn(server.handle_http(std::move(*income)));
        }
    }
    co_return {};
}

int main(int argc, char **argv)
{
    { // init thread pool
        int count_thread = 0;
        if (count_thread == 0)
        {
            count_thread = std::thread::hardware_concurrency();
        }
        pool::ThreadPoolManager::GetInstance()->Init(count_thread);
    }
    std::string serveAt = "127.0.0.1:8080";
    if (argc > 1) {
        serveAt = argv[1];
    }
    co_main(amain(serveAt));
    return 0;
}