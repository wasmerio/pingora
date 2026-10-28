// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(target_os = "linux")]
use log::{debug, error, warn};
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::socket::{
    self, AddressFamily, Backlog, ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg, SockFlag,
    SockType, UnixAddr,
};
#[cfg(target_os = "linux")]
use nix::sys::stat;
#[cfg(target_os = "linux")]
use nix::unistd::{read, write};
use nix::{errno::Errno::EIO, Error, NixPath};
use std::collections::{HashMap, HashSet};
use std::io::Write;
#[cfg(target_os = "linux")]
use std::io::{IoSlice, IoSliceMut};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use std::{thread, time};

// Utilities to transfer file descriptors between sockets, e.g. during graceful upgrades.

/// Container for open file descriptors and their associated bind addresses.
pub struct Fds {
    map: HashMap<String, RawFd>,
}

#[cfg(target_os = "linux")]
const MAGIC_PREFIX: [u8; 8] = [0, b'P', b'I', b'N', b'G', b'F', b'D', b'2'];
#[cfg(target_os = "linux")]
const V2_HEADER_LEN: usize = MAGIC_PREFIX.len() + 8; // magic + fd_count + payload_len
#[cfg(target_os = "linux")]
const MAX_FDS: usize = 32;

impl Fds {
    pub fn new() -> Self {
        Fds {
            map: HashMap::new(),
        }
    }

    pub fn add(&mut self, bind: String, fd: RawFd) {
        self.map.insert(bind, fd);
    }

    pub fn get(&self, bind: &str) -> Option<&RawFd> {
        self.map.get(bind)
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn serialize(&self) -> (Vec<String>, Vec<RawFd>) {
        self.map.iter().map(|(key, val)| (key.clone(), val)).unzip()
    }

    pub fn deserialize(&mut self, binds: Vec<String>, fds: Vec<RawFd>) {
        assert_eq!(binds.len(), fds.len());
        for (bind, fd) in binds.into_iter().zip(fds) {
            self.map.insert(bind, fd);
        }
    }

    pub fn send_to_sock<P>(&self, path: &P) -> Result<usize, Error>
    where
        P: ?Sized + NixPath + std::fmt::Display,
    {
        let (vec_key, vec_fds) = self.serialize();
        let mut ser_buf: [u8; 2048] = [0; 2048];
        let ser_key_size = serialize_vec_string(&vec_key, &mut ser_buf);
        send_fds_to(vec_fds, &ser_buf[..ser_key_size], path, None)
    }

    pub fn get_from_sock<P>(&mut self, path: &P) -> Result<(), Error>
    where
        P: ?Sized + NixPath + std::fmt::Display,
    {
        let mut de_buf: [u8; 2048] = [0; 2048];
        let (fds, bytes) = get_fds_from(path, &mut de_buf, None)?;
        let keys = deserialize_vec_string(&de_buf[..bytes])?;
        self.deserialize(keys, fds);
        Ok(())
    }

    /// Close and remove inherited listening fds whose bind addresses are absent from `keep`.
    ///
    /// An unclaimed `SO_REUSEPORT` socket remains active without an acceptor and can black-hole
    /// connections. Removing it also prevents it from being transferred to the next process.
    /// Returns the addresses removed from the table.
    #[cfg(unix)]
    pub fn close_unclaimed(&mut self, keep: &HashSet<String>) -> Vec<String> {
        let mut closed = Vec::new();
        self.map.retain(|bind, fd| {
            if keep.contains(bind) {
                return true;
            }
            if let Err(e) = nix::unistd::close(*fd) {
                log::warn!(
                    "Failed to close orphaned inherited listening socket fd {fd} ({bind}): {e}"
                );
            }
            closed.push(bind.clone());
            false
        });
        closed
    }
}

fn serialize_vec_string(vec_string: &[String], mut buf: &mut [u8]) -> usize {
    // There are many ways to do this. Serde is probably the way to go
    // But let's start with something simple: space separated strings
    let joined = vec_string.join(" ");
    // TODO: check the buf is large enough
    buf.write(joined.as_bytes()).unwrap()
}

fn deserialize_vec_string(buf: &[u8]) -> Result<Vec<String>, Error> {
    let joined = std::str::from_utf8(buf).map_err(|_| Error::EINVAL)?;
    Ok(joined.split_ascii_whitespace().map(String::from).collect())
}

#[cfg(target_os = "linux")]
pub fn get_fds_from<P>(
    path: &P,
    payload: &mut [u8],
    max_retry: Option<usize>,
) -> Result<(Vec<RawFd>, usize), Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    let max_retry = max_retry.unwrap_or(MAX_RETRY);

    let listen_fd = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let unix_addr = UnixAddr::new(path).unwrap();
    // clean up old sock
    match nix::unistd::unlink(path) {
        Ok(()) => {
            debug!("unlink {} done", path);
        }
        Err(e) => {
            // Normal if file does not exist
            debug!("unlink {} failed: {}", path, e);
            // TODO: warn if exist but not able to unlink
        }
    };
    socket::bind(listen_fd.as_raw_fd(), &unix_addr).unwrap();

    /* sock is created before we change user, need to give permission */
    stat::fchmodat(
        // SAFETY: AT_FDCWD is a well-defined POSIX sentinel constant used by *at() syscalls
        // to indicate the current working directory. It is not a real file descriptor and does
        // not require ownership or lifetime guarantees.
        unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
        path,
        stat::Mode::from_bits_truncate(0o666),
        stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();

    socket::listen(
        &listen_fd,
        Backlog::new(8).expect("8 is well within SOMAXCONN"),
    )
    .unwrap();

    let fd = match accept_with_retry_timeout(listen_fd.as_raw_fd(), max_retry) {
        Ok(fd) => fd,
        Err(e) => {
            error!("Giving up reading socket from: {path}, error: {e:?}");
            //cleanup
            if nix::unistd::close(listen_fd).is_ok() {
                nix::unistd::unlink(path).unwrap();
            }
            return Err(e);
        }
    };

    // Own the transfer connection so every exit path closes it, including failures
    // while receiving either the legacy or framed protocol.
    // SAFETY: accept returned this descriptor and no other owner was created.
    let conn = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = conn.as_raw_fd();

    // Decide protocol version by peeking at the magic prefix.
    let mut prefix_buf = [0u8; MAGIC_PREFIX.len()];
    let mut peek_polls = 0;
    let is_v2 = loop {
        match socket::recv(fd, &mut prefix_buf, MsgFlags::MSG_PEEK) {
            Ok(0) => break false,
            Ok(n) => {
                if n < MAGIC_PREFIX.len() {
                    peek_polls += 1;
                    if peek_polls >= MAX_NONBLOCKING_POLLS {
                        break false;
                    }
                    thread::sleep(NONBLOCKING_POLL_INTERVAL);
                    continue;
                }
                break prefix_buf == MAGIC_PREFIX;
            }
            Err(Errno::EAGAIN) => {
                peek_polls += 1;
                if peek_polls >= MAX_NONBLOCKING_POLLS {
                    break false;
                }
                thread::sleep(NONBLOCKING_POLL_INTERVAL);
            }
            Err(_) => break false,
        }
    };

    let (fds, bytes) = if is_v2 {
        receive_v2(fd, payload, &MAGIC_PREFIX, V2_HEADER_LEN)?
    } else {
        receive_v1(fd, payload)?
    };

    //cleanup
    if nix::unistd::close(listen_fd).is_ok() {
        nix::unistd::unlink(path).unwrap();
    }

    Ok((fds, bytes))
}

#[cfg(not(target_os = "linux"))]
pub fn get_fds_from<P>(
    _path: &P,
    _payload: &mut [u8],
    _max_retry: Option<usize>,
) -> Result<(Vec<RawFd>, usize), Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    log::error!("Upgrade is not currently supported outside of Linux platforms");
    Err(Errno::ECONNREFUSED)
}

#[cfg(target_os = "linux")]
const MAX_RETRY: usize = 5;
#[cfg(target_os = "linux")]
const RETRY_INTERVAL: time::Duration = time::Duration::from_secs(1);
#[cfg(target_os = "linux")]
const NONBLOCKING_POLL_INTERVAL: time::Duration = time::Duration::from_millis(500);
#[cfg(target_os = "linux")]
const MAX_NONBLOCKING_POLLS: usize = 20;

#[cfg(target_os = "linux")]
fn accept_with_retry_timeout(listen_fd: i32, max_retry: usize) -> Result<i32, Error> {
    let mut retried = 0;
    loop {
        match socket::accept(listen_fd) {
            Ok(fd) => return Ok(fd),
            Err(e) => {
                if retried > max_retry {
                    return Err(e);
                }
                match e {
                    Errno::EAGAIN => {
                        error!(
                            "No incoming socket transfer, sleep {RETRY_INTERVAL:?} and try again"
                        );
                        retried += 1;
                        thread::sleep(RETRY_INTERVAL);
                    }
                    _ => {
                        error!("Error accepting socket transfer: {e}");
                        return Err(e);
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn receive_v1(fd: RawFd, payload: &mut [u8]) -> Result<(Vec<RawFd>, usize), Error> {
    let mut io_vec = [IoSliceMut::new(payload); 1];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS]);
    let msg: RecvMsg<UnixAddr> = socket::recvmsg(
        fd,
        &mut io_vec,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .unwrap();

    let mut fds: Vec<RawFd> = Vec::new();
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(mut vec_fds) = cmsg {
            fds.append(&mut vec_fds)
        } else {
            warn!("Unexpected control messages: {cmsg:?}")
        }
    }

    Ok((fds, msg.bytes))
}

#[cfg(target_os = "linux")]
fn read_exact_retry(fd: RawFd, mut buf: &mut [u8]) -> Result<(), Error> {
    let mut nonblocking_polls = 0;
    while !buf.is_empty() {
        match read(unsafe { BorrowedFd::borrow_raw(fd) }, buf) {
            Ok(0) => return Err(EIO),
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
            }
            Err(Errno::EAGAIN) => {
                nonblocking_polls += 1;
                if nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                    return Err(Errno::EAGAIN);
                }
                thread::sleep(NONBLOCKING_POLL_INTERVAL);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn receive_v2(
    fd: RawFd,
    payload: &mut [u8],
    magic: &[u8],
    header_len: usize,
) -> Result<(Vec<RawFd>, usize), Error> {
    let mut header = vec![0u8; header_len];
    read_exact_retry(fd, &mut header)?;
    if header[..magic.len()] != *magic {
        return Err(Error::EINVAL);
    }

    let fd_count =
        u32::from_be_bytes(header[magic.len()..magic.len() + 4].try_into().unwrap()) as usize;
    let payload_len =
        u32::from_be_bytes(header[magic.len() + 4..magic.len() + 8].try_into().unwrap()) as usize;

    if payload_len > payload.len() {
        return Err(Error::EINVAL);
    }

    read_exact_retry(fd, &mut payload[..payload_len])?;

    let mut fds: Vec<RawFd> = Vec::with_capacity(fd_count);
    let mut nonblocking_polls = 0;

    while fds.len() < fd_count {
        let mut data = [0u8; 1];
        let mut io_vec = [IoSliceMut::new(&mut data)];
        let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS]);

        match socket::recvmsg::<UnixAddr>(
            fd,
            &mut io_vec,
            Some(&mut cmsg_buf),
            MsgFlags::MSG_CMSG_CLOEXEC,
        ) {
            Ok(msg) => {
                if msg.bytes == 0 {
                    return Err(EIO);
                }
                if msg.flags.contains(MsgFlags::MSG_CTRUNC)
                    || msg.flags.contains(MsgFlags::MSG_TRUNC)
                {
                    return Err(EIO);
                }
                for cmsg in msg.cmsgs()? {
                    if let ControlMessageOwned::ScmRights(mut vec_fds) = cmsg {
                        fds.append(&mut vec_fds)
                    }
                }
            }
            Err(Errno::EAGAIN) => {
                nonblocking_polls += 1;
                if nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                    return Err(Errno::EAGAIN);
                }
                thread::sleep(NONBLOCKING_POLL_INTERVAL);
            }
            Err(e) => return Err(e),
        }
    }

    if fds.len() != fd_count {
        for fd in fds {
            let _ = nix::unistd::close(fd);
        }
        return Err(EIO);
    }

    Ok((fds, payload_len))
}

#[cfg(target_os = "linux")]
fn write_all_retry(fd: RawFd, mut buf: &[u8], max_nonblocking_polls: usize) -> Result<(), Error> {
    let mut polls = 0;
    while !buf.is_empty() {
        match write(unsafe { BorrowedFd::borrow_raw(fd) }, buf) {
            Ok(0) => return Err(EIO),
            Ok(n) => buf = &buf[n..],
            Err(Errno::EAGAIN) => {
                polls += 1;
                if polls >= max_nonblocking_polls {
                    return Err(Errno::EAGAIN);
                }
                thread::sleep(NONBLOCKING_POLL_INTERVAL);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn send_fds_v1(
    fd: RawFd,
    fds: &[RawFd],
    payload: &[u8],
    path: &dyn std::fmt::Display,
    nonblocking_polls: &mut usize,
) -> Result<usize, Error> {
    let io_vec = [IoSlice::new(payload); 1];
    let scm = socket::ControlMessage::ScmRights(fds);
    let cmsg = [scm; 1];
    loop {
        match socket::sendmsg(fd, &io_vec, &cmsg, MsgFlags::empty(), None::<&UnixAddr>) {
            Ok(result) => break Ok(result),
            Err(e) => match e {
                /* handle nonblocking IO */
                Errno::EAGAIN => {
                    *nonblocking_polls += 1;
                    if *nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                        error!(
                            "Sendmsg() not ready after retries when sending socket to: {}",
                            path
                        );
                        break Err(e);
                    }
                    warn!(
                        "Sendmsg() not ready, will try again in {:?}",
                        NONBLOCKING_POLL_INTERVAL
                    );
                    thread::sleep(NONBLOCKING_POLL_INTERVAL);
                }
                _ => break Err(e),
            },
        }
    }
}

#[cfg(target_os = "linux")]
fn send_fds_v2(
    fd: RawFd,
    fds: &[RawFd],
    payload: &[u8],
    path: &dyn std::fmt::Display,
    nonblocking_polls: &mut usize,
) -> Result<usize, Error> {
    let mut header = vec![0u8; V2_HEADER_LEN];
    header[..MAGIC_PREFIX.len()].copy_from_slice(&MAGIC_PREFIX);
    header[MAGIC_PREFIX.len()..MAGIC_PREFIX.len() + 4]
        .copy_from_slice(&(fds.len() as u32).to_be_bytes());
    header[MAGIC_PREFIX.len() + 4..].copy_from_slice(&(payload.len() as u32).to_be_bytes());

    write_all_retry(fd, &header, MAX_NONBLOCKING_POLLS)?;
    write_all_retry(fd, payload, MAX_NONBLOCKING_POLLS)?;

    let mut sent_fds = 0;
    while sent_fds < fds.len() {
        let end = usize::min(sent_fds + MAX_FDS, fds.len());
        let data = [0xFFu8; 1];
        let io_vec = [IoSlice::new(&data)];
        let scm = ControlMessage::ScmRights(&fds[sent_fds..end]);
        let cmsg = [scm; 1];

        loop {
            match socket::sendmsg(fd, &io_vec, &cmsg, MsgFlags::empty(), None::<&UnixAddr>) {
                Ok(_) => break,
                Err(e) => match e {
                    /* handle nonblocking IO */
                    Errno::EAGAIN => {
                        *nonblocking_polls += 1;
                        if *nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                            error!(
                                "Sendmsg() not ready after retries when sending socket to: {}",
                                path
                            );
                            return Err(e);
                        }
                        warn!(
                            "Sendmsg() not ready, will try again in {:?}",
                            NONBLOCKING_POLL_INTERVAL
                        );
                        thread::sleep(NONBLOCKING_POLL_INTERVAL);
                    }
                    _ => return Err(e),
                },
            }
        }

        sent_fds = end;
    }

    Ok(header.len() + payload.len())
}

#[cfg(target_os = "linux")]
pub fn send_fds_to<P>(
    fds: Vec<RawFd>,
    payload: &[u8],
    path: &P,
    max_retry: Option<usize>,
) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    let max_retry = max_retry.unwrap_or(MAX_RETRY);

    let send_fd = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    let unix_addr = UnixAddr::new(path)?;
    let mut retried = 0;
    let mut nonblocking_polls = 0;

    let conn_result: Result<usize, Error> = loop {
        match socket::connect(send_fd.as_raw_fd(), &unix_addr) {
            Ok(_) => break Ok(0),
            Err(e) => match e {
                /* If the new process hasn't created the upgrade sock we'll get an ENOENT.
                ECONNREFUSED may happen if the sock wasn't cleaned up
                and the old process tries sending before the new one is listening.
                EACCES may happen if connect() happen before the correct permission is set */
                Errno::ENOENT | Errno::ECONNREFUSED | Errno::EACCES => {
                    /*the server is not ready yet*/
                    retried += 1;
                    if retried > max_retry {
                        error!(
                            "Max retry: {} reached. Giving up sending socket to: {}, error: {:?}",
                            max_retry, path, e
                        );
                        break Err(e);
                    }
                    warn!("server not ready, will try again in {RETRY_INTERVAL:?}");
                    thread::sleep(RETRY_INTERVAL);
                }
                /* handle nonblocking IO */
                Errno::EINPROGRESS => {
                    nonblocking_polls += 1;
                    if nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                        error!("Connect() not ready after retries when sending socket to: {path}",);
                        break Err(e);
                    }
                    warn!("Connect() not ready, will try again in {NONBLOCKING_POLL_INTERVAL:?}",);
                    thread::sleep(NONBLOCKING_POLL_INTERVAL);
                }
                _ => {
                    error!("Error sending socket to: {path}, error: {e:?}");
                    break Err(e);
                }
            },
        }
    };

    let result = match conn_result {
        Ok(_) if fds.len() <= MAX_FDS => send_fds_v1(
            send_fd.as_raw_fd(),
            fds.as_slice(),
            payload,
            &path,
            &mut nonblocking_polls,
        ),
        Ok(_) => send_fds_v2(
            send_fd.as_raw_fd(),
            fds.as_slice(),
            payload,
            &path,
            &mut nonblocking_polls,
        ),
        Err(_) => conn_result,
    };

    nix::unistd::close(send_fd).unwrap();
    result
}

#[cfg(not(target_os = "linux"))]
pub fn send_fds_to<P>(
    _fds: Vec<RawFd>,
    _payload: &[u8],
    _path: &P,
    _max_retry: Option<usize>,
) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    Ok(0)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;
    use log::{debug, error};
    use nix::fcntl;

    fn init_log() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_add_get() {
        init_log();
        let mut fds = Fds::new();
        let key = "1.1.1.1:80".to_string();
        fds.add(key.clone(), 128);
        assert_eq!(128, *fds.get(&key).unwrap());
    }

    #[test]
    fn test_table_serde() {
        init_log();
        let mut fds = Fds::new();
        let key1 = "1.1.1.1:80".to_string();
        fds.add(key1.clone(), 128);
        let key2 = "1.1.1.1:443".to_string();
        fds.add(key2.clone(), 129);

        let (k, v) = fds.serialize();
        let mut fds2 = Fds::new();
        fds2.deserialize(k, v);

        assert_eq!(128, *fds2.get(&key1).unwrap());
        assert_eq!(129, *fds2.get(&key2).unwrap());
    }

    #[test]
    fn test_vec_string_serde() {
        init_log();
        let vec_str: Vec<String> = vec!["aaaa".to_string(), "bbb".to_string()];
        let mut ser_buf: [u8; 1024] = [0; 1024];
        let size = serialize_vec_string(&vec_str, &mut ser_buf);
        let de_vec_string = deserialize_vec_string(&ser_buf[..size]).unwrap();
        assert_eq!(de_vec_string.len(), 2);
        assert_eq!(de_vec_string[0], "aaaa");
        assert_eq!(de_vec_string[1], "bbb");
    }

    #[test]
    fn test_send_receive_fds() {
        init_log();
        let dumb_fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();

        // receiver need to start in another thread since it is blocking
        let child = thread::spawn(move || {
            let mut buf: [u8; 64] = [0; 64];
            let (fds, bytes) =
                get_fds_from("/tmp/pingora_fds_receive.sock", &mut buf, None).unwrap();
            debug!("{:?}", fds);
            assert_eq!(1, fds.len());
            assert_eq!(32, bytes);
            assert_eq!(1, buf[0]);
            assert_eq!(1, buf[31]);
        });

        let fds = vec![dumb_fd.as_raw_fd()];
        let buf: [u8; 32] = [1; 32];
        match send_fds_to(fds, &buf, "/tmp/pingora_fds_receive.sock", None) {
            Ok(sent) => {
                assert!(sent > 0);
            }
            Err(e) => {
                error!("{:?}", e);
                panic!()
            }
        }

        child.join().unwrap();
    }

    /// How many fds in this process refer to a unix socket bound to `path`.
    ///
    /// Reads the socket inodes bound to `path` from /proc/net/unix, then scans
    /// /proc/self/fd for descriptors pointing at them. Filtering by path keeps this
    /// unaffected by unrelated descriptors opened by tests running in parallel.
    fn unix_socket_fds_bound_to(path: &str) -> usize {
        let unix = std::fs::read_to_string("/proc/net/unix").unwrap();
        let inodes: HashSet<&str> = unix
            .lines()
            .filter_map(|line| {
                let mut cols = line.split_whitespace();
                let inode = cols.nth(6)?;
                (cols.next() == Some(path)).then_some(inode)
            })
            .collect();
        if inodes.is_empty() {
            return 0;
        }
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
            .filter(|target| {
                target
                    .to_str()
                    .and_then(|t| t.strip_prefix("socket:["))
                    .and_then(|t| t.strip_suffix(']'))
                    .is_some_and(|inode| inodes.contains(inode))
            })
            .count()
    }

    #[test]
    fn test_receive_does_not_leak_fds() {
        init_log();
        const SOCK: &str = "/tmp/pingora_fds_receive3.sock";

        let dumb_fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();

        // receiver need to start in another thread since it is blocking
        let child = thread::spawn(move || {
            let mut buf: [u8; 32] = [0; 32];
            let (fds, _) = get_fds_from(SOCK, &mut buf, None).unwrap();
            assert_eq!(1, fds.len());

            // The received listener is kept for the lifetime of the process, so it must
            // not be inherited by unrelated children across exec().
            let flags = fcntl::fcntl(
                // SAFETY: the fd was just received and stays open for this call.
                unsafe { BorrowedFd::borrow_raw(fds[0]) },
                fcntl::FcntlArg::F_GETFD,
            )
            .unwrap();
            assert!(
                fcntl::FdFlag::from_bits_truncate(flags).contains(fcntl::FdFlag::FD_CLOEXEC),
                "fd received over SCM_RIGHTS is missing FD_CLOEXEC"
            );

            // The accepted connection is only needed during the transfer itself.
            assert_eq!(
                0,
                unix_socket_fds_bound_to(SOCK),
                "the accepted transfer socket was left open"
            );

            // Don't leak the descriptors this test just received.
            for fd in fds {
                // SAFETY: received over SCM_RIGHTS just above and not owned anywhere else.
                drop(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        });

        let fds = vec![dumb_fd.as_raw_fd()];
        let buf: [u8; 32] = [1; 32];
        send_fds_to(fds, &buf, SOCK, None).unwrap();

        child.join().unwrap();
    }

    #[test]
    fn test_serde_via_socket() {
        init_log();
        let mut fds = Fds::new();
        let key1 = "1.1.1.1:80".to_string();
        let dumb_fd1 = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        fds.add(key1.clone(), dumb_fd1.as_raw_fd());
        let key2 = "1.1.1.1:443".to_string();
        let dumb_fd2 = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        fds.add(key2.clone(), dumb_fd2.as_raw_fd());

        let child = thread::spawn(move || {
            let mut fds2 = Fds::new();
            fds2.get_from_sock("/tmp/pingora_fds_receive2.sock")
                .unwrap();
            assert!(*fds2.get(&key1).unwrap() > 0);
            assert!(*fds2.get(&key2).unwrap() > 0);
        });

        fds.send_to_sock("/tmp/pingora_fds_receive2.sock").unwrap();
        child.join().unwrap();
    }

    #[test]
    fn test_v1_compatibility() {
        init_log();
        let dumb_fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();

        // receiver thread uses legacy path (v1)
        let child = thread::spawn(move || {
            let mut buf: [u8; 64] = [0; 64];
            let (fds, bytes) =
                get_fds_from("/tmp/pingora_fds_receive_v1.sock", &mut buf, None).unwrap();
            assert_eq!(1, fds.len());
            assert_eq!(16, bytes);
            assert_eq!(7, buf[0]);
            assert_eq!(7, buf[15]);
        });

        let payload = [7u8; 16];
        let fds = vec![dumb_fd.as_raw_fd()];
        legacy_send_fds("/tmp/pingora_fds_receive_v1.sock", &fds, &payload).unwrap();
        child.join().unwrap();
    }

    #[test]
    fn test_v2_chunked_send_more_than_32() {
        init_log();
        let mut owned_fds = Vec::new();
        let mut fds: Vec<RawFd> = Vec::new();
        for _ in 0..40 {
            let fd = socket::socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )
            .unwrap();
            fds.push(fd.as_raw_fd());
            owned_fds.push(fd);
        }

        let payload = [9u8; 24];
        let child = thread::spawn(move || {
            let mut buf: [u8; 64] = [0; 64];
            let (recv_fds, bytes) =
                get_fds_from("/tmp/pingora_fds_receive_v2.sock", &mut buf, None).unwrap();
            assert_eq!(40, recv_fds.len());
            assert_eq!(payload.len(), bytes);
            assert_eq!(9, buf[0]);
            assert_eq!(9, buf[payload.len() - 1]);
            assert_eq!(
                0,
                unix_socket_fds_bound_to("/tmp/pingora_fds_receive_v2.sock")
            );
            for fd in recv_fds {
                // SAFETY: each descriptor was received above and has no other owner.
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                let flags = fcntl::fcntl(&fd, fcntl::FcntlArg::F_GETFD).unwrap();
                assert!(
                    fcntl::FdFlag::from_bits_truncate(flags).contains(fcntl::FdFlag::FD_CLOEXEC)
                );
            }
        });

        send_fds_to(fds, &payload, "/tmp/pingora_fds_receive_v2.sock", None).unwrap();
        child.join().unwrap();
    }

    #[test]
    fn test_send_fds_to_respects_configurable_timeout() {
        init_log();
        use std::time::Instant;

        let dumb_fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();

        let fds = vec![dumb_fd.as_raw_fd()];
        let buf: [u8; 32] = [1; 32];

        let start = Instant::now();
        let result = send_fds_to(fds, &buf, "/tmp/pingora_test_config_send.sock", Some(2));
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() >= 2,
            "Expected at least 2 seconds, got {:?}",
            elapsed
        );
        assert!(
            elapsed.as_secs() < 4,
            "Expected less than 4 seconds, got {:?}",
            elapsed
        );
    }

    #[test]
    fn test_get_fds_from_respects_configurable_timeout() {
        init_log();
        use std::time::Instant;

        let mut buf: [u8; 32] = [0; 32];

        let start = Instant::now();
        let result = get_fds_from("/tmp/pingora_test_config_receive.sock", &mut buf, Some(2));
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() >= 2,
            "Expected at least 2 seconds, got {:?}",
            elapsed
        );
        assert!(
            elapsed.as_secs() < 4,
            "Expected less than 4 seconds, got {:?}",
            elapsed
        );
    }

    fn legacy_send_fds(path: &str, fds: &[RawFd], payload: &[u8]) -> Result<(), Error> {
        const MAX_RETRY: usize = 5;
        const RETRY_INTERVAL: time::Duration = time::Duration::from_millis(200);

        let send_fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK,
            None,
        )?;
        let unix_addr = UnixAddr::new(path)?;
        let mut retry = 0;
        loop {
            match socket::connect(send_fd.as_raw_fd(), &unix_addr) {
                Ok(_) => break,
                Err(e) => match e {
                    Errno::ENOENT | Errno::ECONNREFUSED | Errno::EACCES => {
                        retry += 1;
                        if retry > MAX_RETRY {
                            return Err(e);
                        }
                        thread::sleep(RETRY_INTERVAL);
                    }
                    _ => return Err(e),
                },
            }
        }

        let io_vec = [IoSlice::new(payload)];
        let scm = socket::ControlMessage::ScmRights(fds);
        let cmsg = [scm; 1];
        socket::sendmsg(
            send_fd.as_raw_fd(),
            &io_vec,
            &cmsg,
            socket::MsgFlags::empty(),
            None::<&UnixAddr>,
        )?;

        nix::unistd::close(send_fd).unwrap();
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod close_unclaimed_tests {
    use super::Fds;
    use std::collections::HashSet;
    use std::io::{ErrorKind, Read};
    use std::os::unix::io::{FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    // Closure is observed by reading the other end of a socket pair, which
    // reports end-of-file exactly when its peer is gone. Checking the descriptor
    // *number* would be racy: numbers are process-wide and reassigned
    // lowest-free-first, so a concurrent test in this binary can be handed the
    // number just closed and make it valid again first. Observing ends are
    // non-blocking, so a descriptor that wrongly stayed open fails an assertion
    // rather than hanging.
    //
    // A second owning handle would turn a wrongly closed descriptor into an I/O
    // safety abort of the whole binary, so `Fds` gets raw numbers.

    #[test]
    fn closes_only_unclaimed_fds() {
        let (mut keep_peer, keep_local) = UnixStream::pair().unwrap();
        let (mut drop_peer, drop_local) = UnixStream::pair().unwrap();
        keep_peer.set_nonblocking(true).unwrap();
        drop_peer.set_nonblocking(true).unwrap();
        let keep_fd = keep_local.into_raw_fd();

        let mut fds = Fds::new();
        fds.add("127.0.0.1:80".to_string(), keep_fd);
        fds.add("127.0.0.1:9090".to_string(), drop_local.into_raw_fd());

        let keep: HashSet<String> = ["127.0.0.1:80".to_string()].into_iter().collect();
        let closed = fds.close_unclaimed(&keep);

        assert_eq!(closed, vec!["127.0.0.1:9090".to_string()]);
        assert_eq!(*fds.get("127.0.0.1:80").unwrap(), keep_fd);
        assert!(fds.get("127.0.0.1:9090").is_none());

        // Dropping the map entry is not enough: the descriptor itself has to be
        // closed, which is the leak this function exists to prevent.
        assert!(
            matches!(drop_peer.read(&mut [0u8; 1]), Ok(0)),
            "the unclaimed descriptor was not closed"
        );
        assert!(
            matches!(keep_peer.read(&mut [0u8; 1]), Err(e) if e.kind() == ErrorKind::WouldBlock),
            "the claimed descriptor was closed"
        );

        // `Fds` does not close on drop.
        // SAFETY: asserted open just above, and no other owner remains.
        drop(unsafe { OwnedFd::from_raw_fd(keep_fd) });
    }

    #[test]
    fn empty_keep_set_closes_everything() {
        let (mut peer, local) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();

        let mut fds = Fds::new();
        fds.add("127.0.0.1:9090".to_string(), local.into_raw_fd());

        let closed = fds.close_unclaimed(&HashSet::new());

        assert_eq!(closed, vec!["127.0.0.1:9090".to_string()]);
        assert!(fds.is_empty());
        assert!(
            matches!(peer.read(&mut [0u8; 1]), Ok(0)),
            "the unclaimed descriptor was not closed"
        );
    }
}
