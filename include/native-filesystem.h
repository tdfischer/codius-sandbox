#ifndef NATIVE_FILESYSTEM_H
#define NATIVE_FILESYSTEM_H

#include "filesystem.h"
#include <string>
#include <map>

/**
 * A filesystem that directly interacts with the host's local filesystem
 */
class NativeFilesystem : public Filesystem {
public:
  /**
   * Constructor. Accepts a path that is the root of this filesystem
   *
   * @param root Root of this filesystem
   */
  NativeFilesystem(const std::string& root);
  Continuation<int> open(const char* name, int flags, int mode) override;
  Continuation<ssize_t> read(int fd, void* buf, size_t count) override;
  Continuation<int> close (int fd) override;
  Continuation<int> fstat (int fd, struct stat* buf) override;
  Continuation<int> getdents (int fd, struct linux_dirent* dirs, unsigned int count) override;
  Continuation<off_t> lseek (int fd, off_t offset, int whence) override;
  Continuation<ssize_t> write(int fd, void* buf, size_t count) override;
  Continuation<int> access (const char* name, int mode) override;
  Continuation<int> stat (const char* name, struct stat* buf) override;
  Continuation<int> lstat (const char* name, struct stat* buf) override;
  Continuation<ssize_t> readlink(const char* path, char* buf, size_t bufsize);

private:
  std::string m_root;
  std::map<int, std::string> m_openFiles;
};

#endif // NATIVE_FILESYSTEM_H
