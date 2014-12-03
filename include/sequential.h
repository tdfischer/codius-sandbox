#ifndef SEQUENTIAL_H
#define SEQUENTIAL_H

#include <initializer_list>
#include <vector>
#include <functional>
#include <uv.h>

class Sequential {
public:
  Sequential(std::initializer_list<std::function<void()> > funcList) :
    m_functions (funcList)
  {
    uv_async_init (uv_default_loop(), &m_async, doNext);
    m_async.data = this;
  }

  bool next()
  {
    if (m_functions.size()) {
      auto i = m_functions.begin();
      (*i)();
      m_functions.erase (i);
    }
    return m_functions.size() > 0;
  }

  bool hasNext()
  {
    return m_functions.size() > 0;
  }

private:
  std::vector<std::function<void()> > m_functions;
  uv_async_t m_async;

  static void doNext (uv_async_t* async, int status)
  {
    Sequential* self = static_cast<Sequential*> (async->data);
    self->next();
    if (self->hasNext())
      uv_async_send (&self->m_async);
    else
      uv_close (reinterpret_cast<uv_handle_t*> (&self->m_async), nullptr);
  }
};

#endif // SEQUENTIAL_H
