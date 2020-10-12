use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use nix::Error;

pub struct SerialPort {
    fd: RawFd,
}

impl SerialPort {
    pub fn new(path: &Path) -> io::Result<Self> {
        use nix::fcntl::OFlag;
        use nix::sys::termios;

        let fd = nix::fcntl::open(
            path,
            OFlag::O_RDWR | OFlag::O_NOCTTY,
            nix::sys::stat::Mode::empty(),
        )
        .unwrap();

        let mut cfg = termios::tcgetattr(fd).unwrap();
        cfg.input_flags = termios::InputFlags::empty();
        cfg.output_flags = termios::OutputFlags::empty();
        cfg.control_flags = termios::ControlFlags::empty();
        cfg.local_flags = termios::LocalFlags::empty();
        termios::cfmakeraw(&mut cfg);
        cfg.input_flags |= termios::InputFlags::IGNBRK;
        cfg.control_flags |= termios::ControlFlags::CREAD;
        cfg.control_flags |= termios::ControlFlags::CRTSCTS;
        termios::cfsetospeed(&mut cfg, termios::BaudRate::B115200).unwrap();
        termios::cfsetispeed(&mut cfg, termios::BaudRate::B115200).unwrap();
        termios::cfsetspeed(&mut cfg, termios::BaudRate::B115200).unwrap();
        termios::tcsetattr(fd, termios::SetArg::TCSANOW, &cfg).unwrap();
        termios::tcflush(fd, termios::FlushArg::TCIOFLUSH).unwrap();

        Ok(Self { fd })
    }
}

impl AsRawFd for SerialPort {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

fn to_io_error(e: Error) -> io::Error {
    match e {
        Error::Sys(errno) => errno.into(),
        e => io::Error::new(io::ErrorKind::InvalidInput, e),
    }
}

impl io::Read for SerialPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        nix::unistd::read(self.fd, buf).map_err(|e| to_io_error(e))
    }
}

impl io::Write for SerialPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        nix::unistd::write(self.fd, buf).map_err(|e| to_io_error(e))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
