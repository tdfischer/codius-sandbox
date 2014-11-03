#ifndef VFS_H
#define VFS_H

#include "sandbox.h"
#include <memory>
#include <vector>

class Filesystem;
class DirentBuilder;

class File {
public:
  File(int localFD, std::shared_ptr<Filesystem>& fs);

  using Ptr = std::shared_ptr<File>;

  int localFD() const;
  int virtualFD() const;
  std::shared_ptr<Filesystem> fs() const;

private:
  static int s_nextFD;
  int m_localFD;
  int m_virtualFD;
  std::shared_ptr<Filesystem> m_fs;
};

class Filesystem {
public:
  Filesystem();

  virtual int open(const char* name, int flags) = 0;
  virtual ssize_t read(int fd, void* buf, size_t count) = 0;
  virtual int close(int fd) = 0;
  virtual int fstat(int fd, struct stat* buf) = 0;
  virtual int getdents(int fd, struct linux_dirent* dirs, unsigned int count) = 0;
  virtual int openat(int fd, const char* filename, int flags, mode_t mode) = 0;
};

class NativeFilesystem : public Filesystem {
public:
  NativeFilesystem(const std::string& root);
  virtual int open(const char* name, int flags);
  virtual ssize_t read(int fd, void* buf, size_t count);
  virtual int close(int fd);
  virtual int fstat(int fd, struct stat* buf);
  virtual int getdents(int fd, struct linux_dirent* dirs, unsigned int count);
  virtual int openat(int fd, const char* filename, int flags, mode_t mode);

private:
  std::string m_root;
  std::map<int, std::string> m_openFiles;
};

class DirentBuilder {
public:
  void append(const std::string& name);
  std::vector<char> data() const;

private:
  std::vector<std::string> m_names;
  void push(std::vector<char>& ret, const std::string& name) const;
};

class VFS {
public:
  VFS(Sandbox* sandbox);

  Sandbox::SyscallCall handleSyscall(const Sandbox::SyscallCall& call);
  std::string getFilename(Sandbox::Address addr) const;
  std::pair<std::string, std::shared_ptr<Filesystem> > getFilesystem(const std::string& path) const;
  File::Ptr getFile(int fd) const;

  inline bool isVirtualFD (int fd) const {return fd >= firstVirtualFD;}
  static constexpr int firstVirtualFD = 4096;

  void mountFilesystem(const std::string& path, std::shared_ptr<Filesystem> fs);
  std::string getMountedFilename(const std::string& path) const;

private:
  Sandbox* m_sbox;
  std::map<std::string, std::shared_ptr <Filesystem>> m_mountpoints;
  std::map<int, File::Ptr> m_openFiles;
  std::vector<std::string> m_whitelist;

  bool isWhitelisted(const std::string& str);

  void do_open(Sandbox::SyscallCall& call);
  void do_close(Sandbox::SyscallCall& call);
  void do_read(Sandbox::SyscallCall& call);
  void do_fstat(Sandbox::SyscallCall& call);
  void do_getdents(Sandbox::SyscallCall& call);
  void do_openat(Sandbox::SyscallCall& call);

  File::Ptr makeFile (int fd, std::shared_ptr<Filesystem>& fs);
};

#endif // VFS_H
