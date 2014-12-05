#include "vfs.h"
#include <dirent.h>
#include <memory.h>
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <cassert>
#include <error.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm-generic/posix_types.h>
#include "dirent-builder.h"

VFS::VFS(Sandbox* sandbox)
  : m_sbox (sandbox)
{
  m_whitelist.push_back ("/lib64/tls/x86_64/libc.so.6");
  m_whitelist.push_back ("/lib64/tls/x86_64/libdl.so.2");
  m_whitelist.push_back ("/lib64/tls/x86_64/librt.so.1");
  m_whitelist.push_back ("/lib64/tls/x86_64/libpthread.so.0");
  m_whitelist.push_back ("/lib64/tls/libc.so.6");
  m_whitelist.push_back ("/lib64/tls/libdl.so.2");
  m_whitelist.push_back ("/lib64/tls/librt.so.1");
  m_whitelist.push_back ("/lib64/tls/libstdc++.so.6");
  m_whitelist.push_back ("/lib64/tls/libm.so.6");
  m_whitelist.push_back ("/lib64/tls/libgcc_s.so.1");
  m_whitelist.push_back ("/lib64/tls/libpthread.so.0");
  m_whitelist.push_back ("/lib64/x86_64/libc.so.6");
  m_whitelist.push_back ("/lib64/x86_64/libdl.so.2");
  m_whitelist.push_back ("/lib64/x86_64/librt.so.1");
  m_whitelist.push_back ("/lib64/libc.so.6");
  m_whitelist.push_back ("/lib64/libdl.so.2");
  m_whitelist.push_back ("/lib64/librt.so.1");
  m_whitelist.push_back ("/lib64/libgcc_s.so.1");
  m_whitelist.push_back ("/lib64/libpthread.so.0");

  m_whitelist.push_back ("/lib64/libstdc++.so.6");
  m_whitelist.push_back ("/lib64/libm.so.6");

  m_whitelist.push_back ("/etc/ld.so.cache");
  m_whitelist.push_back ("/etc/ld.so.preload");

  m_whitelist.push_back ("/proc/self/exe");
}

void
VFS::mountFilesystem(const std::string& path, std::shared_ptr<Filesystem> fs)
{
  m_mountpoints.insert (std::make_pair (path, fs));
}

std::string
VFS::getFilename(pid_t pid, Sandbox::Address addr) const
{
  std::vector<char> buf (1024);
  m_sbox->copyString (pid, addr, buf.size(), buf.data());
  return std::string (buf.data());
}

File::Ptr
VFS::getFile(int fd) const
{
  assert (isVirtualFD (fd));
  return m_openFiles.at(fd);
}

Continuation<int>
File::close()
{
  if (m_localFD > 0) {
    return m_fs->close(m_localFD).then (Continuation<int>([=](int ret){
      m_localFD = -1;
      return ret;
    }));
  }
  return -EBADF;
}

std::pair<std::string, std::shared_ptr<Filesystem> >
VFS::getFilesystem(const std::string& path) const
{
  std::string searchPath (path);
  std::string longest_mount;
  if (path[0] == '.')
    searchPath = m_cwd->path() + path;
  for(auto i = m_mountpoints.cbegin(); i != m_mountpoints.cend(); i++) {
    if (searchPath.compare(0, i->first.size(), i->first) == 0) {
      std::string newPath (searchPath.substr (i->first.size()-1));
      return std::make_pair (newPath, i->second);
    }
  }
  return std::make_pair (std::string(), nullptr);
}

int File::s_nextFD = VFS::firstVirtualFD;

File::File(int localFD, const std::string& path, std::shared_ptr<Filesystem>& fs)
  : m_localFD (localFD),
    m_path (path),
    m_fs (fs)
{
  //FIXME: gcc-4.8 lacks stdatomic.h, so we're stuck with gcc builtins :(
  //see also: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=58016
  m_virtualFD = __sync_fetch_and_add (&s_nextFD, 1);
}

std::string
File::path() const
{
  return m_path;
}

Continuation<Sandbox::SyscallCall>
VFS::do_readlink (const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  std::string fname = getFilename (call.pid, call.args[0]);
  if (!isWhitelisted (fname)) {
    ret.id = -1;
    std::pair<std::string, std::shared_ptr<Filesystem> > fs = getFilesystem (fname);
    if (fs.second) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        std::vector<char>* buf = new std::vector<char> (call.args[2]);
        fs.second->readlink (fs.first.c_str(), buf->data(), buf->size()).then(
          Continuation<ssize_t>([=](ssize_t v) mutable {
            Sandbox::SyscallCall ret (call);
            ret.returnVal = v;
            m_sbox->writeData (ret.pid, ret.args[1], std::min(buf->size(), ret.returnVal), buf->data());
            delete buf;
            cont (ret);
          })
        );
      });
    } else {
      ret.returnVal = -ENOENT;
    }
  }
  return ret;
}

Continuation<Sandbox::SyscallCall>
VFS::do_openat (const Sandbox::SyscallCall& call)
{
  std::string fname = getFilename (call.pid, call.args[1]);

  if (fname[0] != '/') {
    std::string fdPath;
    if (call.args[0] == AT_FDCWD) {
      fdPath = m_cwd->path();
    } else if (isVirtualFD (call.args[0])) {
      File::Ptr file = getFile (call.args[0]);
      fdPath = file->path();
    }
    fname = fdPath + fname;
  }

  return openFile (call, fname, call.args[2], call.args[3]);
}


File::~File ()
{
  close();
}

File::Ptr
VFS::makeFile (int fd, const std::string& path, std::shared_ptr<Filesystem>& fs)
{
  File::Ptr f(new File (fd, path, fs));
  m_openFiles.insert (std::make_pair (f->virtualFD(), f));
  return f;
}

Continuation<Sandbox::SyscallCall>
VFS::do_access (const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  std::string fname = getFilename (call.pid, call.args[0]);
  if (!isWhitelisted (fname)) {
    ret.id = -1;
    std::pair<std::string, std::shared_ptr<Filesystem> > fs = getFilesystem (fname);
    if (fs.second) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        fs.second->access (fs.first.c_str(), call.args[1]).then(Continuation<int>([=](int v) mutable {
          Continuation<Sandbox::SyscallCall> finish (cont);
          ret.returnVal = v;
          cont (ret);
        }));
      });
    } else {
      ret.returnVal = -ENOENT;
    }
  }

  return ret;
}

Continuation<Sandbox::SyscallCall>
VFS::openFile(const Sandbox::SyscallCall& call, const std::string& fname, int flags, mode_t mode)
{
  Sandbox::SyscallCall ret (call);
  if (!isWhitelisted (fname)) {
    ret.id = -1;
    std::pair<std::string, std::shared_ptr<Filesystem> > fs = getFilesystem (fname);
    if (fs.second) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        Debug() << "Opening" << fs.first;
        fs.second->open (fs.first.c_str(), flags, mode).then(Continuation<int>([=](int fd) mutable {
          if (fd) {
            File::Ptr file (makeFile (fd, fname, fs.second));
            ret.returnVal = file->virtualFD();
            cont (ret);
          } else {
            ret.returnVal = -errno;
            cont (ret);
          }
        }));
      });
    } else {
      ret.returnVal = -ENOENT;
    }
  } else {
    Debug() << "Whitelisted" << fname;
  }
  return Continuation<Sandbox::SyscallCall> (ret);
}

Continuation<Sandbox::SyscallCall>
VFS::do_open (const Sandbox::SyscallCall& call)
{
  std::string fname = getFilename (call.pid, call.args[0]);
  return openFile (call, fname, call.args[1], call.args[2]);
}

int
File::virtualFD() const
{
  return m_virtualFD;
}

int
File::localFD() const
{
  return m_localFD;
}

std::shared_ptr<Filesystem>
File::fs() const
{
  return m_fs;
}

Continuation<Sandbox::SyscallCall>
VFS::do_close (const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  if (isVirtualFD (ret.args[0])) {
    ret.id = -1;
    File::Ptr fh = getFile (ret.args[0]);
    if (fh) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        fh->close().then(Continuation<int>([=](int v) mutable {
          ret.returnVal = v;
          m_openFiles.erase (fh->virtualFD());
          cont (ret);
        }));
      });
    } else {
      ret.returnVal = -EBADF;
    }
  }
  return ret;
}

Continuation<ssize_t>
File::read(void* buf, size_t count)
{
  return m_fs->read (m_localFD, buf, count);
}

Continuation<Sandbox::SyscallCall>
VFS::do_read (const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  if (isVirtualFD (ret.args[0])) {
    ret.id = -1;
    File::Ptr file = getFile (ret.args[0]);
    std::vector<char>* buf = new std::vector<char> (ret.args[2]);
    if (file) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        file->read (buf->data(), buf->size()).then(Continuation<ssize_t>([=](ssize_t readCount) mutable {
          if (readCount >= 0) {
            m_sbox->writeData (ret.pid, ret.args[1], readCount, buf->data());
            ret.returnVal = readCount;
          } else {
            ret.returnVal = -errno;
          }
          delete buf;
          cont (ret);
        }));
      });
    } else {
      ret.returnVal = -EBADF;
    }
  }
  return ret;
}

Continuation<int>
File::fstat (struct stat* buf)
{
  return m_fs->fstat (m_localFD, buf);
}

Continuation<Sandbox::SyscallCall>
VFS::do_fstat (const Sandbox::SyscallCall& call)
{
  if (isVirtualFD (call.args[0])) {
    Sandbox::SyscallCall ret (call);
    File::Ptr file = getFile (ret.args[0]);
    ret.id = -1;
    if (file) {
      std::shared_ptr<struct stat> sbuf (new struct stat);
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        file->fstat (sbuf.get()).then(Continuation<int>([=](int v) mutable {
          ret.returnVal = v;
          if (ret.returnVal == 0)
            m_sbox->writeData(ret.pid, ret.args[1], sizeof (sbuf.get()), (char*)sbuf.get());
          cont (ret);
        }));
      });
    } else {
      ret.returnVal = -EBADF;
      return ret;
    }
  }
  return call;
}

Continuation<int>
File::getdents(struct linux_dirent* dirs, unsigned int count)
{
  return m_fs->getdents (m_localFD, dirs, count);
}

Continuation<Sandbox::SyscallCall>
VFS::do_write (const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  if (isVirtualFD (ret.args[0])) {
    File::Ptr file = getFile (ret.args[0]);
    ret.id = -1;
    if (file) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        std::vector<char>* buf = new std::vector<char>(ret.args[2]);
        m_sbox->copyData (ret.pid, ret.args[1], buf->size(), buf->data());
        file->write(buf->data(), buf->size()).then(Continuation<ssize_t >([=](ssize_t v) mutable {
          ret.returnVal = v;
          delete buf;
          cont (ret);
        }));
      });
    };
  }
  return ret;
}

Continuation<Sandbox::SyscallCall>
VFS::do_getdents (const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  if (isVirtualFD (ret.args[0])) {
    File::Ptr file = getFile (ret.args[0]);
    ret.id = -1;
    if (file) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        std::vector<char>* buf = new std::vector<char> (ret.args[2]);
        struct linux_dirent* dirents = (struct linux_dirent*)buf->data();
        file->getdents (dirents, buf->size()).then(Continuation<int>([=](int v) mutable {
          ret.returnVal = v;
          if ((int)ret.returnVal > 0)
            m_sbox->writeData(ret.pid, ret.args[1], ret.returnVal, buf->data());
          cont (ret);
        }));
      });
    } else {
      ret.returnVal = -EBADF;
    }
  }
  return ret;
}

Continuation<Sandbox::SyscallCall>
VFS::do_fchdir(const Sandbox::SyscallCall& call)
{
  return Continuation<Sandbox::SyscallCall>([=]() {
    Sandbox::SyscallCall ret (call);
    File::Ptr fh = getFile (ret.args[0]);
    if (fh) {
      m_cwd = fh;
      ret.returnVal = 0;
    } else {
      ret.returnVal = -EBADF;
    }
    return ret;
  });
}

Continuation<Sandbox::SyscallCall>
VFS::do_chdir(const Sandbox::SyscallCall& call)
{
  return Continuation<Sandbox::SyscallCall>([=](Sandbox::SyscallCall, Continuation<Sandbox::SyscallCall> finish) {
    Sandbox::SyscallCall ret (call);
    std::string fname = getFilename (ret.pid, ret.args[0]);
    setCWD (fname).then(Continuation<int>([&](int result) {
      ret.returnVal = result;
      finish (ret);
    }));
  });
}

std::string
VFS::getCWD() const
{
  assert (m_cwd);
  return m_cwd->path();
}

Continuation<int>
VFS::setCWD(const std::string& fname)
{
  std::string trimmedFname (fname);
  if (trimmedFname[fname.length()-1] == '/')
    trimmedFname = std::string(fname.cbegin(), fname.cend()-1);
  std::pair<std::string, std::shared_ptr<Filesystem> > fs = getFilesystem (trimmedFname);
  if (fs.second) {
    return Continuation<int>([=](Continuation<int> cont) mutable {
      fs.second->open (fs.first.c_str(), O_DIRECTORY, 0).then(Continuation<int>([=](int fd) mutable {
        m_cwd = File::Ptr (new File (fd, trimmedFname, fs.second));
        return 0;
      }));
    });
  } else {
    return -ENOENT;
  }
}

#define HANDLE_CALL(x) case SYS_##x: return do_##x(call);break;

Continuation<Sandbox::SyscallCall>
VFS::handleSyscall(const Sandbox::SyscallCall& call)
{
  switch (call.id) {
    HANDLE_CALL (open);
    HANDLE_CALL (close);
    HANDLE_CALL (read);
    HANDLE_CALL (fstat);
    HANDLE_CALL (getdents);
    HANDLE_CALL (openat);
    HANDLE_CALL (lseek);
    HANDLE_CALL (write);
    HANDLE_CALL (access);
    HANDLE_CALL (chdir);
    HANDLE_CALL (stat);
    HANDLE_CALL (lstat);
    HANDLE_CALL (getcwd);
    HANDLE_CALL (readlink);
    default:
      return call;
  }
}

#undef HANDLE_CALL

Continuation<off_t>
File::lseek(off_t offset, int whence)
{
  return m_fs->lseek(m_localFD, offset, whence);
}

Continuation<ssize_t>
File::write(void* buf, size_t count)
{
  return m_fs->write (m_localFD, buf, count);
}

Continuation<Sandbox::SyscallCall>
VFS::do_getcwd(const Sandbox::SyscallCall& call)
{
  return Continuation<Sandbox::SyscallCall>([=]() {
    Sandbox::SyscallCall ret (call);
    std::string cwd = getCWD();
    m_sbox->writeData (ret.pid, ret.args[0], std::min (ret.args[1], cwd.length()), cwd.c_str());
    ret.returnVal = cwd.length();
    return ret;
  });
}

Continuation<Sandbox::SyscallCall>
VFS::do_lstat(const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  std::string fname = getFilename (ret.pid, ret.args[0]);
  if (!isWhitelisted (fname)) {
    ret.id = -1;
    std::pair<std::string, std::shared_ptr<Filesystem> > fs = getFilesystem (fname);
    if (fs.second) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        std::shared_ptr<struct stat> sbuf (new struct stat);
        fs.second->lstat (fname.c_str(), sbuf.get()).then(Continuation<int>([=](int v) mutable {
          ret.returnVal = v;
          if (ret.returnVal == 0)
            m_sbox->writeData (ret.pid, ret.args[1], sizeof (*sbuf.get()), (char*)sbuf.get());
          cont (ret);
        }));
      });
    } else {
      ret.returnVal = -ENOENT;
    }
  }
  return ret;
}

Continuation<Sandbox::SyscallCall>
VFS::do_stat(const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  std::string fname = getFilename (ret.pid, ret.args[0]);
  if (!isWhitelisted (fname)) {
    ret.id = -1;
    std::pair<std::string, std::shared_ptr<Filesystem> > fs = getFilesystem (fname);
    if (fs.second) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        std::shared_ptr<struct stat> sbuf (new struct stat);
        fs.second->stat (fname.c_str(), sbuf.get()).then(Continuation<int>([=](int v) mutable {
          ret.returnVal = v;
          if (ret.returnVal == 0)
            m_sbox->writeData (ret.pid, ret.args[1], sizeof (*sbuf.get()), (char*)sbuf.get());
          cont (ret);
        }));
      });
    } else {
      ret.returnVal = -ENOENT;
    }
  }
  return ret;
}

Continuation<Sandbox::SyscallCall>
VFS::do_lseek(const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret (call);
  if (isVirtualFD (ret.args[0])) {
    ret.id = -1;
    File::Ptr file = getFile (ret.args[0]);
    if (file) {
      return Continuation<Sandbox::SyscallCall>([=](Continuation<Sandbox::SyscallCall> cont) mutable {
        file->lseek (ret.args[1], ret.args[2]).then(Continuation<ssize_t>([=](ssize_t v) mutable {
          ret.returnVal = v;
          cont (ret);
        }));
      });
    } else {
      ret.returnVal = -EBADF;
    }
  }
  return ret;
}

bool
VFS::isWhitelisted(const std::string& str)
{
  for (auto i = m_whitelist.cbegin(); i != m_whitelist.cend(); i++) {
    if (str == *i)
      return true;
  }
  return false;
}

