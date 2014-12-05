#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <unistd.h>

#include "continuation.h"

/**
 * Interface for implementing concrete filesystems
 *
 * Each function is an implementation of a specific POSIX syscall.
 *
 * @see VFS
 * @see Syscall manpages
 */
class Filesystem {
public:
  virtual Continuation<int> open(const char* name, int flags, int mode) = 0;
  virtual Continuation<ssize_t> read(int fd, void* buf, size_t count) = 0;
  virtual Continuation<int> close(int fd) = 0;
  virtual Continuation<int> fstat(int fd, struct stat* buf) = 0;
  virtual Continuation<int> getdents(int fd, struct linux_dirent* dirs, unsigned int count) = 0;
  virtual Continuation<off_t> lseek(int fd, off_t offset, int whence) = 0;
  virtual Continuation<ssize_t> write(int fd, void* buf, size_t count) = 0;
  virtual Continuation<int> access(const char* name, int mode) = 0;
  virtual Continuation<int> stat(const char* path, struct stat *buf) = 0;
  virtual Continuation<int> lstat(const char* path, struct stat *buf) = 0;
  virtual Continuation<ssize_t> readlink(const char* path, char* buf, size_t bufsize) = 0;
};

#endif // FILESYSTEM_H
