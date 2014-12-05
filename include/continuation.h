#ifndef CONTINUATION_H
#define CONTINUATION_H

#include <functional>
#include <uv.h>
#include <cassert>

#include "debug.h"

template<typename Result>
class Continuation {
public:
  using FunctionType = std::function<void(Result, Continuation<Result> cont)>;
  using EndFunctionType = std::function<void(Result)>;
  using ReturnFunctionType = std::function<Result()>;

  Continuation(FunctionType&& func) :
    m_exec (new Executor (std::move (func)))
  {}

  Continuation(ReturnFunctionType&& func) :
    Continuation([=](Result, Continuation<Result> cont) {cont (func());})
  {}

  Continuation(EndFunctionType&& func) :
    Continuation([=](Result res, Continuation<Result> cont) {func (res);cont (res);})
  {}

  Continuation(Result&& result) :
    Continuation([=](Result res, Continuation<Result> cont) {cont (res);})
  {}

  Continuation(const Result& result) :
    Continuation([=](Result res, Continuation<Result> cont) {cont (res);})
  {}

  Continuation(Continuation&& other) :
    m_exec (other.m_exec->ref())
  {
    other.m_exec->unref();
    other.m_exec = nullptr;
  }

  Continuation(const Continuation& other) :
    m_exec (other.m_exec->ref())
  {}

  ~Continuation()
  {
    if (m_exec) {
      m_exec->unref();
      m_exec = nullptr;
    }
  }

  Continuation<Result>&& then(Continuation<Result>&& next)
  {
    assert (m_exec->next == nullptr);
    m_exec->next = next.m_exec->ref();
    return std::move (next);
  }

  void operator()(Result&& res)
  {
    finish (std::move (res));
  }

  void operator()(Result& res)
  {
    finish (res);
  }

  void finish(Result& res)
  {
    m_exec->finish (res);
  }

  void finish(Result&& res)
  {
    m_exec->finish (std::move (res));
  }

private:
  struct Executor {
    FunctionType func;
    Executor* next;
    Result prevResult;
    bool queued;
    uv_async_t async;
    int refcount;

    Executor(FunctionType&& func) :
      func (std::move (func)),
      next (nullptr),
      queued (false),
      refcount (1)
    {
      uv_async_init (uv_default_loop(), &async, asyncExec);
      async.data = this;
    }

    void unref()
    {
      refcount--;
      Debug() << refcount;
      assert (refcount < 10);
      assert (refcount >= 0);
      if (refcount == 0)
        enqueue();
    }

    Executor* ref()
    {
      refcount++;
      Debug() << refcount;
      return this;
    }

    ~Executor()
    {
      assert (refcount == 0);
      if (next)
        next->unref();
    }

    static void asyncClosed(uv_handle_t* handle)
    {
      Executor* self = static_cast<Executor*> (handle->data);
      delete self;
    }

    static void asyncExec(uv_async_t* async, int status)
    {
      Executor* self = static_cast<Executor*> (async->data);
      self->exec();
    }

    void enqueue()
    {
      if (!queued)
        uv_async_send (&async);
      queued = true;
    }

    void exec()
    {
      assert (refcount == 0);
      func (prevResult, Continuation<Result> (this));
    }

    void finish(Result& res)
    {
      finish (Result (res));
    }
    
    void finish(Result&& res)
    {
      if (next) {
        next->prevResult = std::move (res);
        func = nullptr;
        uv_close (reinterpret_cast<uv_handle_t*> (&async), asyncClosed);
      }
    }
  };

  Executor* m_exec;

  Continuation(Executor* exec) :
    m_exec (exec->ref())
  {}
};

#endif // CONTINUATION_H
