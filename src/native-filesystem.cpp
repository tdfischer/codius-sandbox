#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "native-filesystem.h"

Continuation<int>
NativeFilesystem::open(const char* name, int flags, int mode)
{
  std::string newName (name);
  newName = m_root + "/" + newName;
  return ::open (newName.c_str(), flags, mode);
}

Continuation<int>
NativeFilesystem::close(int fd)
{
  return ::close (fd);
}

Continuation<ssize_t>
NativeFilesystem::read(int fd, void* buf, size_t count)
{
  return ::read (fd, buf, count);
}

Continuation<int>
NativeFilesystem::fstat(int fd, struct stat* buf)
{
  return ::fstat (fd, buf);
}

Continuation<int>
NativeFilesystem::getdents(int fd, struct linux_dirent* dirs, unsigned int count)
{
  return ::syscall (SYS_getdents, fd, dirs, count);
}

Continuation<off_t>
NativeFilesystem::lseek(int fd, off_t offset, int whence)
{
  return ::lseek (fd, offset, whence);
}

NativeFilesystem::NativeFilesystem(const std::string& root)
  : Filesystem()
  , m_root (root)
{
}

Continuation<ssize_t>
NativeFilesystem::write(int fd, void* buf, size_t count)
{
  return ::write (fd, buf, count);
}

Continuation<int>
NativeFilesystem::access(const char* name, int mode)
{
  return ::access (name, mode);
}

Continuation<int>
NativeFilesystem::stat(const char* name, struct stat* buf)
{
  return ::stat (name, buf);
}

Continuation<int>
NativeFilesystem::lstat(const char* name, struct stat* buf)
{
  return ::lstat (name, buf);
}

Continuation<ssize_t>
NativeFilesystem::readlink(const char* name, char* buf, size_t bufsize)
{
  return ::readlink (name, buf, bufsize);
}
