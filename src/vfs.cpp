#include "vfs.h"
#include <dirent.h>
#include <memory.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <cassert>

struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[];
  /*
  char pad
  char d_type;
  */
};

void
DirentBuilder::append(const std::string& name) {
  m_names.push_back (name);
}

std::vector<char>
DirentBuilder::data() const {
  std::vector<char> ret;
  for (auto i = m_names.cbegin(); i != m_names.cend(); i++) {
    push (ret, *i);
  }
  return ret;
}

//FIXME: This needs to be able to support non-regular file types
void
DirentBuilder::push(std::vector<char>& ret, const std::string& name) const {
  static long inode = 4242;
  unsigned short reclen;
  char* d_type;

  reclen = sizeof (linux_dirent) + name.size() + sizeof (char) * 3;
  off_t start = ret.size();
  ret.resize (start + reclen);
  linux_dirent* ent = reinterpret_cast<linux_dirent*>(&ret.data()[start]);
  ent->d_ino = inode++;
  ent->d_reclen = reclen;
  memcpy (ent->d_name, name.data(), name.size() + 1);
  d_type = reinterpret_cast<char*>(ent + reclen - 1);
  *d_type = DT_REG;
}

VFS::VFS(Sandbox* sandbox)
  : m_sbox (sandbox)
{
  m_whitelist.push_back ("/lib64/tls/x86_64/libc.so.6");
  m_whitelist.push_back ("/lib64/tls/libc.so.6");
  m_whitelist.push_back ("/lib64/x86_64/libc.so.6");
  m_whitelist.push_back ("/lib64/libc.so.6");
  m_whitelist.push_back ("/etc/ld.so.cache");
}

void
VFS::mountFilesystem(const std::string& path, std::shared_ptr<Filesystem> fs)
{
  m_mountpoints.insert (std::make_pair (path, fs));
}

std::string
VFS::getFilename(Sandbox::Address addr) const
{
  std::vector<char> buf (1024);
  m_sbox->copyString (addr, buf.size(), buf.data());
  return std::string (buf.data());
}

File::Ptr
VFS::getFile(int fd) const
{
  assert (isVirtualFD (fd));
  return m_openFiles.at(fd);
}

int
File::close()
{
  return m_fs->close(m_localFD);
}

std::pair<std::string, std::shared_ptr<Filesystem> >
VFS::getFilesystem(const std::string& path) const
{
  std::string longest_mount;
  for(auto i = m_mountpoints.cbegin(); i != m_mountpoints.cend(); i++) {
    if (path.compare(0, i->first.size(), i->first) == 0) {
      std::string newPath (path.substr (i->first.size()));
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
  //FIXME: Should be atomic
  m_virtualFD = s_nextFD++;
}

std::string
File::path() const
{
  return m_path;
}

void
VFS::do_openat (Sandbox::SyscallCall& call)
{
  std::string fname = getFilename (call.args[1]);

  if (fname[0] != '/') {
    std::string fdPath;
    if (call.args[0] == AT_FDCWD) {
      fdPath = m_sbox->getCWD();
    } else if (isVirtualFD (call.args[0])) {
      File::Ptr file = getFile (call.args[0]);
      fdPath = file->path();
    }

    fname = fdPath + fname;
  }

  std::cout << "openat resolved to " << fname << std::endl;

  //FIXME: This is copied from do_open. Needs put in a common method
  if (!isWhitelisted (fname)) {
    call.id = -1;
    std::pair<std::string, std::shared_ptr<Filesystem> > fs = getFilesystem (fname);
    if (fs.second) {
      int fd = fs.second->open (fs.first.c_str(), call.args[0]);
      File::Ptr file (makeFile (fd, fname, fs.second));
      call.returnVal = file->virtualFD();
    } else {
      call.returnVal = -ENOENT;
    }
  }
}

File::Ptr
VFS::makeFile (int fd, const std::string& path, std::shared_ptr<Filesystem>& fs)
{
  File::Ptr f(new File (fd, path, fs));
  m_openFiles.insert (std::make_pair (f->virtualFD(), f));
  return f;
}

void
VFS::do_open (Sandbox::SyscallCall& call)
{
  std::string fname = getFilename (call.args[0]);
  if (!isWhitelisted (fname)) {
    call.id = -1;
    std::pair<std::string, std::shared_ptr<Filesystem> > fs = getFilesystem (fname);
    if (fs.second) {
      int fd = fs.second->open (fs.first.c_str(), call.args[0]);
      File::Ptr file (makeFile (fd, fname, fs.second));
      call.returnVal = file->virtualFD();
    } else {
      call.returnVal = -ENOENT;
    }
  }
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

void
VFS::do_close (Sandbox::SyscallCall& call)
{
  if (isVirtualFD (call.args[0])) {
    call.id = -1;
    File::Ptr fh = getFile (call.args[0]);
    if (fh) {
      call.returnVal = fh->close ();
      m_openFiles.erase (fh->virtualFD());
    } else {
      call.returnVal = -EBADF;
    }
  }
}

ssize_t
File::read(void* buf, size_t count)
{
  return m_fs->read (m_localFD, buf, count);
}

void
VFS::do_read (Sandbox::SyscallCall& call)
{
  if (isVirtualFD (call.args[0])) {
    call.id = -1;
    File::Ptr file = getFile (call.args[0]);
    std::vector<char> buf (call.args[2]);
    if (file) {
      ssize_t readCount = file->read (buf.data(), buf.size());
      m_sbox->writeData (call.args[1], buf.size(), buf.data());
      call.returnVal = readCount;
    } else {
      call.returnVal = -EBADF;
    }
  }
}

int
File::fstat (struct stat* buf)
{
  return m_fs->fstat (m_localFD, buf);
}

void
VFS::do_fstat (Sandbox::SyscallCall& call)
{
  if (isVirtualFD (call.args[0])) {
    struct stat sbuf;
    File::Ptr file = getFile (call.args[0]);
    call.id = -1;
    if (file) {
      call.returnVal = file->fstat (&sbuf);
      m_sbox->writeData(call.args[1], sizeof (sbuf), (char*)&sbuf);
    } else {
      call.returnVal = -EBADF;
    }
  }
}

int
File::getdents(struct linux_dirent* dirs, unsigned int count)
{
  return m_fs->getdents (m_localFD, dirs, count);
}

void
VFS::do_getdents (Sandbox::SyscallCall& call)
{
  if (isVirtualFD (call.args[0])) {
    File::Ptr file = getFile (call.args[0]);
    call.id = -1;
    if (file) {
      void* buf = malloc (call.args[2]);
      call.returnVal = file->getdents ((struct linux_dirent*)buf, call.args[2]);
      m_sbox->writeData(call.args[1], call.args[2], (char*)buf);
      free (buf);
    } else {
      call.returnVal = -EBADF;
    }
  }
}

#define HANDLE_CALL(x) case SYS_##x: do_##x(ret);break;

Sandbox::SyscallCall
VFS::handleSyscall(const Sandbox::SyscallCall& call)
{
  Sandbox::SyscallCall ret(call);
  switch (call.id) {
    HANDLE_CALL (open);
    HANDLE_CALL (close);
    HANDLE_CALL (read);
    HANDLE_CALL (fstat);
    HANDLE_CALL (getdents);
    HANDLE_CALL (openat);
    HANDLE_CALL (lseek);
  }
  return ret;
}

#undef HANDLE_CALL

off_t
File::lseek(off_t offset, int whence)
{
  return m_fs->lseek(m_localFD, offset, whence);
}

void
VFS::do_lseek(Sandbox::SyscallCall& call)
{
  if (isVirtualFD (call.args[0])) {
    call.id = -1;
    File::Ptr file = getFile (call.args[0]);
    if (file) {
      call.returnVal = file->lseek (call.args[1], call.args[2]);
    } else {
      call.returnVal = -EBADF;
    }
  }
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

int
NativeFilesystem::open(const char* name, int flags)
{
  std::string newName (name);
  newName = m_root + "/" + newName;
  return ::open (newName.c_str(), flags);
}

int
NativeFilesystem::close(int fd)
{
  return ::close (fd);
}

ssize_t
NativeFilesystem::read(int fd, void* buf, size_t count)
{
  return ::read (fd, buf, count);
}

int
NativeFilesystem::fstat(int fd, struct stat* buf)
{
  return ::fstat (fd, buf);
}

int
NativeFilesystem::getdents(int fd, struct linux_dirent* dirs, unsigned int count)
{
  return ::syscall (SYS_getdents, fd, dirs, count);
}

off_t
NativeFilesystem::lseek(int fd, off_t offset, int whence)
{
  return ::lseek (fd, offset, whence);
}

NativeFilesystem::NativeFilesystem(const std::string& root)
  : Filesystem()
  , m_root (root)
{
}

Filesystem::Filesystem()
{}
