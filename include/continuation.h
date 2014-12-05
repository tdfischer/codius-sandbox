#ifndef CONTINUATION_H
#define CONTINUATION_H

#include <functional>
#include <uv.h>
#include <cassert>

#include "debug.h"

template<typename Result>
class Continuation {
public:
  using FunctionType = std::function<void(const Result, Continuation<Result> cont)>;
  using EndFunctionType = std::function<void(const Result)>;
  using ReturnFunctionType = std::function<Result(void)>;

  Continuation(FunctionType func) :
    m_exec (new Executor (func))
  {}

  Continuation(ReturnFunctionType func) :
    Continuation([=](const Result, Continuation<Result> cont) {
      cont (func());
    })
  {}

  Continuation(EndFunctionType func) :
    Continuation([=](const Result res, Continuation<Result> cont) {
      func (res);
      cont (res);
    })
  {}

  Continuation(const Result result) :
    Continuation([=](const Result res, Continuation<Result> cont) {
      cont (res);
    })
  {
    m_exec->prevResult = result;
  }

  Continuation(Continuation& other) :
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

  void operator()(const Result& res)
  {
    finish (res);
  }

  void finish(const Result& res)
  {
    m_exec->finish (res);
  }

private:
  struct Executor {
    FunctionType func;
    Executor* next;
    Result prevResult;
    bool queued;
    uv_async_t async;
    int refcount;

    Executor(FunctionType& func) :
      func (func),
      next (nullptr),
      queued (false),
      refcount (1)
    {
      uv_async_init (uv_default_loop(), &async, asyncExec);
      async.data = this;
    }

    void unref()
    {
      if (refcount > 0)
        refcount--;
      Debug() << refcount;
      if (refcount == 0)
        enqueue();
    }

    Executor* ref()
    {
      if (refcount > 0)
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
      assert (self->func == nullptr);
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

    void finish(const Result& res)
    {
      if (next) {
        next->prevResult = res;
      }
      func = nullptr;
      uv_close (reinterpret_cast<uv_handle_t*> (&async), asyncClosed);
    }

  };

  Executor* m_exec;

  Continuation(Executor* exec) :
    m_exec (exec->ref())
  {}
};

#endif // CONTINUATION_H
