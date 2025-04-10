
#include <co_async/awaiter/task.hpp>
#include <co_async/co_async.hpp>
#include <co_async/iostream/ssl_socket_stream.hpp>
#include <co_async/std.hpp>

#include "Pool/ThreadPoolManager.hpp"

using namespace co_async;
using namespace std::literals;

struct Worker {
    std::deque<Task<Expected<>>> q;
    std::condition_variable cv;
    std::mutex mtx;
    std::jthread th;

    auto getId()
    {
        return th.get_id();
    }

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

int getIndex(std::thread::id id)
{
    auto current_poller = std::find_if(workers.begin(), workers.end(), [&](auto &it)
    {
        return id == it.getId();
    });
    if (current_poller == workers.end())
        return -1;

    auto idx = std::distance(workers.begin(), current_poller);
    return idx;
}

Worker &getWorker()
{
    static std::atomic_int64_t i = 0;
    return workers[(i++)%16];
}

Worker &getWorker(int i)
{
    return workers[(i++)%16];
}

static Task<Expected<>> curl() {
    HTTPConnectionPool pool;
    std::vector<Task<Expected<>>> res;
    for (std::string path: {"cameras"}) {
        res.push_back(co_bind([&, path] () -> Task<Expected<>> {
            auto conn = co_await co_await pool.connect("https://10.23.18.4:10001");
            HTTPRequest req = {
                .method = "GET",
                .uri = URI::parse("/" + path),
            };
            debug(), "requesting", req;
            auto [res, body] = co_await co_await conn->request_streamed(req, {});
            debug(), "res", res;
            auto content = co_await co_await body.getall();
            debug(), "body", content;
            co_return {};
        }));
    }
    co_await co_await when_all(res);
    co_return {};
}

static Task<Expected<>> amain(std::string serveAt) {
    co_spawn(curl());
    co_await co_await stdio().putline("listening at: "s + serveAt);
    auto listener = co_await co_await listener_bind(co_await AddressResolver().host(serveAt).resolve_one());

    HTTPServer server;
    server.route([](HTTPServer::IO::Ptr &io) -> Task<Expected<>>
    {
        if (auto ws = co_await websocket_server(io)) {
            co_await co_await stdio().putline("Connection"sv);
            ws->on_message([] (co_async::WebSocket &ws, std::string const &message) -> Task<Expected<>> {
                co_await co_await stdio().putline("message received: "s + message);
                co_await co_await ws.send("Got it! "s + message);
                co_return {};
            });
            ws->on_close([] (co_async::WebSocket &ws) -> Task<Expected<>> {
                co_await co_await stdio().putline("Closing connection"sv);
                co_return {};
            });
            ws->on_pong([] (co_async::WebSocket &ws, std::chrono::steady_clock::duration dt) -> Task<Expected<>> {
                co_await co_await stdio().putline("network delay: "s + to_string(
                    std::chrono::duration_cast<std::chrono::milliseconds>(dt).count()) + "ms"s);
                co_return {};
            });
            co_await co_await ws->start();
        }
        else
        {
            auto ctx = io;
            auto index_thread = getIndex(std::this_thread::get_id());
            auto _body = co_await co_await ctx->request_body();
            pool::ThreadPoolManager::GetInstance()->getThreadPool()->submit([ctx, index_thread]() -> concurrencpp::result<void>
            {
                getWorker(index_thread).spawn(co_bind([ctx]() -> Task<Expected<>> {
                    HTTPResponse res = {
                        .status = 200,
                        .headers = {
                            {"content-type", "text/html;charset=utf-8"},
                        },
                    };
                    std::string_view body = "++";
                    co_awaits ctx->response(res, body);
                    co_return {};
                }));
                co_return;
            });
        }
        co_return {};
    });

    for (std::size_t i = 0; i < workers.size(); ++i) {
        workers[i].start(i);
    }

    SSLServerState ssl;
    ssl.initSSLctx("../cert/server.crt", "../cert/server.key");

    while (true) {
        if (auto income = co_await listener_accept(listener)) [[likely]] {
            getWorker().spawn(co_bind([income = std::move(income), &server, &ssl]() mutable -> Task<Expected<>> {
                co_return co_await server.handle_https(std::move(*income), ssl);;
            }));
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
    std::string serveAt = "0.0.0.0:8080";
    if (argc > 1) {
        serveAt = argv[1];
    }
    co_main(amain(serveAt));
    return 0;
}