#include "node-filesystem.h"
#include "node-sandbox.h"
#include <future>
#include <iostream>
#include <memory.h>

using namespace v8;

CodiusNodeFilesystem::CodiusNodeFilesystem(NodeSandbox* sbox)
  : Filesystem(),
    m_sbox (sbox) {}

CodiusNodeFilesystem::VFSResult
CodiusNodeFilesystem::doVFS(const std::string& name, Handle<Value> argv[], int argc)
{
  std::future<Persistent<Value> > ret = m_sbox->doVFS (name, argv, argc);
  Handle<Value> result;
  uv_loop_t*  loop = uv_default_loop ();
  while (ret.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
    uv_run (loop, UV_RUN_ONCE);
  result = ret.get();
  if (result->IsObject()) {
    Handle<Object> resultObj = result->ToObject();
    int err = resultObj->Get (String::NewSymbol ("error"))->ToInt32()->Value();
    Handle<Value> resultValue = resultObj->Get (String::NewSymbol ("result"))->ToObject();
    VFSResult r  = {
      .errnum = err,
      .result = resultValue
    };
    return r;
  }

  ThrowException(Exception::TypeError(String::New("Expected a VFS call return type")));
  VFSResult r = {
    .errnum = ENOSYS,
    .result = Undefined()
  };
  return r;
}

int
CodiusNodeFilesystem::open(const char* name, int flags)
{
  Handle<Value> argv[] = {
    String::New (name),
    Int32::New (flags),
    Int32::New (0) //FIXME: We also need the mode?
  };

  VFSResult ret = doVFS(std::string ("open"), argv, 3);
  if (ret.errnum) {
    return -ret.errnum;
  }

  return ret.result->ToInt32()->Value();
}

ssize_t
CodiusNodeFilesystem::read(int fd, void* buf, size_t count)
{
  return -ENOSYS;
}

int
CodiusNodeFilesystem::close(int fd)
{
  return -ENOSYS;
}

int
CodiusNodeFilesystem::fstat(int fd, struct stat* buf)
{
  return -ENOSYS;
}

int
CodiusNodeFilesystem::getdents(int fd, struct linux_dirent* dirs, unsigned int count)
{
  Handle<Value> argv[] = {
    Int32::New (fd)
  };
  VFSResult ret = doVFS(std::string ("getdents"), argv, 1);
  if (ret.errnum)
    return -ret.errnum;

  DirentBuilder builder;

  Handle<Array> fileList = Handle<Array>::Cast (ret.result);
  for (uint32_t i = 0; i < fileList->Length(); i++) {
    Handle<String> filename = fileList->Get(i)->ToString();
    char buf[filename->Utf8Length()];
    filename->WriteUtf8 (buf, filename->Utf8Length());
    builder.append (std::string (buf));
  }
  std::vector<char> buf;
  buf = builder.data();
  memcpy (dirs, buf.data(), buf.size());
  return buf.size();
}

int
CodiusNodeFilesystem::openat(int fd, const char* filename, int flags, mode_t mode)
{
  return -ENOSYS;
}

