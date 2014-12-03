#ifndef CONTINUATION_H
#define CONTINUATION_H

#include <functional>
#include <uv.h>

#include "debug.h"

template<typename Result>
class Continuation {
public:
  using FunctionType = std::function<void(Result, Continuation<Result>* continuation)>;
  using ReturnFunctionType = std::function<Result(Result)>;
  using EmptyFunctionType = std::function<void()>;

  Continuation(FunctionType&& func, Result&& initial = Result()) :
    m_func (std::move (func)),
    m_next (nullptr),
    m_prevResult (std::move (initial))
  {
    uv_async_init (uv_default_loop(), &m_async, asyncExec);
    m_async.data = this;
  }

  Continuation(ReturnFunctionType&& func, Result&& initial = Result()):
    Continuation([=](Result res, Continuation<Result>* cont){cont->finish (func (res));}, std::move (initial)) {};

  Continuation(EmptyFunctionType&& func, Result&& initial = Result()) :
    Continuation([=](Result res) {func();return res;}, std::move (initial)) {};

  Continuation(Result&& value = Result()) :
    Continuation([=]{}, std::move (value)) {};

  ~Continuation()
  {
    exec();
    uv_close (reinterpret_cast<uv_handle_t*> (&m_async), nullptr);
  }

  Continuation<Result>* then(FunctionType&& next)
  {
    m_next = new Continuation<Result> (std::move (next));
    return m_next;
  }

  Continuation<Result>* then(ReturnFunctionType&& next)
  {
    return then([=](Result&& prevRes, Continuation<Result>* cont) {
      cont->finish (next (prevRes));
    });
  }

  Continuation<Result>* then(EmptyFunctionType&& next)
  {
    return then([=](Result&& res) {
        next();
        return res;
    });
  }

  void finish(Result&& res)
  {
    if (m_next) {
      m_next->m_prevResult = std::move (res);
    }
    finish();
  }

  void finish()
  {
    if (m_next) {
      Debug() << "Exec next";
      m_next->start();
    } else {
      Debug() << "End of chain";
    }
  }

private:
  FunctionType m_func;
  Continuation<Result>* m_next;
  Result m_prevResult;
  uv_async_t m_async;

  void exec()
  {
    m_func (m_prevResult, this);
    finish();
  }

  static void asyncExec(uv_async_t* async, int status)
  {
    Continuation* self = static_cast<Continuation*> (async->data);
    self->exec();
  }

  void start()
  {
    uv_async_send (&m_async);
  }
};

#endif // CONTINUATION_H
