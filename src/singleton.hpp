#pragma once

namespace ov
{
template <class T> class Singleton
{
  public:
    virtual ~Singleton() = default;

    static T *GetInstance()
    {
        static T instance;
        return &instance;
    }

  protected:
    Singleton() = default;

  private:
};
} // namespace ov
