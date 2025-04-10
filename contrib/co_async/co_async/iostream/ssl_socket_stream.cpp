#include <co_async/awaiter/task.hpp>
#include <co_async/iostream/socket_stream.hpp>
#include <co_async/iostream/ssl_socket_stream.hpp>
#include <co_async/iostream/stream_base.hpp>
#include <co_async/net/socket_proxy.hpp>
#include <co_async/platform/error_handling.hpp>
#include <co_async/platform/fs.hpp>
#include <co_async/platform/platform_io.hpp>
#include <co_async/platform/socket.hpp>
#include <co_async/utils/pimpl.hpp>
#include <co_async/utils/string_utils.hpp>

namespace co_async {

template<typename T>
using deleted_unique_ptr = std::unique_ptr<T,std::function<void(T*)>>;

#define BUFFER_SIZE 512

namespace {
struct SSLSocketStream : Stream {
private:
    SocketStream raw;
    BIO *readBIO;
    BIO *writeBIO;
    std::unique_ptr<char> _buffer;
    deleted_unique_ptr<SSL> ssl_client = nullptr;

    public:
    explicit SSLSocketStream(SocketHandle file) : raw(std::move(file)) 
    {
        _buffer = std::unique_ptr<char>(new char[BUFFER_SIZE]);
    }

    Task<Expected<>> doSSLHandshake()
    {
        while (!SSL_is_init_finished(ssl_client.get()))
        {
            SSL_do_handshake(ssl_client.get());
            int bytesToWrite = BIO_read(writeBIO, _buffer.get(), BUFFER_SIZE);
            if (bytesToWrite > 0)
            {
                auto e = co_await raw.raw_write({_buffer.get(), (size_t)bytesToWrite});
                if (!e)
                {
                    if (e.has_error())
                        co_return CO_ASYNC_ERROR_FORWARD(e);
                    else
                        co_return std::errc::broken_pipe;
                }
            }
            else
            {
                auto e = co_await raw.raw_read({_buffer.get(), BUFFER_SIZE});
                if (!e)
                {
                    if (e.has_error())
                        co_return CO_ASYNC_ERROR_FORWARD(e);
                    else
                        co_return std::errc::broken_pipe;
                }
                size_t receivedBytes = *e;
                if (receivedBytes > 0) {
                    BIO_write(readBIO, _buffer.get(), receivedBytes);
                }

                if (receivedBytes == 0)
                    co_return std::errc::broken_pipe;
            }
        }
        co_return {};
    }

protected:

    void setSSL(SSL *ssl_, bool is_client = false)
    {
        ssl_client = deleted_unique_ptr<SSL>(ssl_,
        [](SSL *ssl)
        {
            if (ssl)
                SSL_free(ssl);
        });

        readBIO  = BIO_new(BIO_s_mem());
        writeBIO = BIO_new(BIO_s_mem());

        SSL_set_bio(ssl_client.get(), readBIO, writeBIO);
        if (is_client)
            SSL_set_connect_state(ssl_client.get()); // Client
        else
            SSL_set_accept_state(ssl_client.get()); // Server
    }

public:

    Task<Expected<>> raw_flush() override
    {
        BIO_reset(writeBIO);
        BIO_reset(readBIO);
        co_return {};
    }

    Task<Expected<std::size_t>> raw_read(std::span<char> buffer) override
    {
        // SSL_read overrides buffer
        while (raw.get())
        {
            int sizeUnencryptBytes = SSL_read(ssl_client.get(), buffer.data(), buffer.size());
            if (sizeUnencryptBytes < 0)
                switch (int err = SSL_get_error(ssl_client.get(), sizeUnencryptBytes)) {
                    case SSL_ERROR_WANT_READ:
                        break;
                    default:
                        co_return 0;
                }
            else
                co_return sizeUnencryptBytes;

            auto e = co_await raw.raw_read({_buffer.get(), BUFFER_SIZE});
            if (!e)
            {
                if (e.has_error())
                    co_return CO_ASYNC_ERROR_FORWARD(e);
                else
                    co_return std::errc::broken_pipe;
            }
            size_t receivedBytes = *(e);
            if (receivedBytes > 0)
                BIO_write(readBIO, _buffer.get(), receivedBytes);

            if (receivedBytes == 0)
                co_return std::errc::broken_pipe;
        }
        co_return 0;
    }

    Task<Expected<std::size_t>> raw_write(std::span<char const> buffer) override
    {
        if (buffer.size() == 0)
            co_return {};

        // SSL_write overrides buffer
        uint64_t send_byte = 0;
        do {
            int sizeUnencryptBytes = SSL_write(ssl_client.get(), buffer.data() + send_byte, buffer.size() - send_byte);
            if (sizeUnencryptBytes <= 0)
                break;

            send_byte += sizeUnencryptBytes;
            do {
                int bytesToWrite = BIO_read(writeBIO, _buffer.get(), BUFFER_SIZE);
                if (bytesToWrite > 0)
                {
                    auto e = co_await raw.raw_write({_buffer.get(), (size_t)bytesToWrite});
                    if (!e)
                    {
                        if (e.has_error())
                            co_return CO_ASYNC_ERROR_FORWARD(e);
                        else
                            co_return std::errc::broken_pipe;
                    }
                    size_t sendBytes = *e;
                    if (sendBytes == 0)
                        co_return std::errc::broken_pipe;
                }
                else
                {
                    break;
                }
            } while (true);
        } while (send_byte < buffer.size());
        co_return send_byte;
    }

    Task<> raw_close() override
    {
        SSL_shutdown(ssl_client.get());
        co_await Stream::raw_close();
        co_await raw.raw_close();
        co_return;
    }

    void raw_timeout(std::chrono::steady_clock::duration timeout) override 
    {
        raw.raw_timeout(timeout);
    }
};

struct SSLServerSocketStream : public SSLSocketStream
{
public:
    explicit SSLServerSocketStream(SocketHandle file, SSL_CTX *ctx)
    : SSLSocketStream(std::move(file)) {
        auto ssl = SSL_new(ctx);
        if (ssl == NULL)
            throw std::logic_error("Error create ssl client");
        setSSL(ssl);
    }
};

struct SSLClientSocketStream : SSLSocketStream {
public:
    explicit SSLClientSocketStream(SocketHandle file,
                                   SSL_CTX *ctx,
                                   char const *host)
        : SSLSocketStream(std::move(file))
    {
        auto ssl = SSL_new(ctx);
        if (ssl == NULL)
            throw std::logic_error("Error create ssl client");
        SSL_set_tlsext_host_name(ssl, host);
        setSSL(ssl, true);
    }

    void ssl_reset(char const *host, bool resume) {}

    std::string ssl_get_selected_protocol()
    {
        return {};
    }
};
} // namespace

Task<Expected<OwningStream>>
ssl_connect(char const *host, int port, SSL_CTX *ctx,
            std::string_view proxy, std::chrono::steady_clock::duration timeout) {
    auto conn =
        co_await co_await socket_proxy_connect(host, port, proxy, timeout);
    auto ssl_stream = std::make_unique<SSLClientSocketStream>(std::move(conn), ctx, host);
    ssl_stream->raw_timeout(timeout);
    auto e = co_await ssl_stream->doSSLHandshake();
    if (!e)
    {
        co_await ssl_stream->raw_close();
        if (e.has_error())
            co_return CO_ASYNC_ERROR_FORWARD(e);
        else
            co_return std::errc::broken_pipe;
    }
    co_return OwningStream(std::move(ssl_stream));
}

Task<Expected<OwningStream>>
ssl_accept(SocketHandle file, SSL_CTX *ctx,
            std::chrono::steady_clock::duration timeout) {
    auto ssl_stream = std::make_unique<SSLServerSocketStream>(std::move(file), ctx);
    ssl_stream->raw_timeout(timeout);
    auto e = co_await ssl_stream->doSSLHandshake();
    if (!e)
    {
        co_await ssl_stream->raw_close();
        if (e.has_error())
            co_return CO_ASYNC_ERROR_FORWARD(e);
        else
            co_return std::errc::broken_pipe;
    }
    co_return OwningStream(std::move(ssl_stream));
}

} // namespace co_async
