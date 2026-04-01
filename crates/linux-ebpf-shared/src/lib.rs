#![no_std]

pub const PATH_LEN: usize = 256;
pub const COMM_LEN: usize = 16;
pub const IP_LEN: usize = 16;

pub const EVENT_KIND_PROCESS_START: u8 = 1;
pub const EVENT_KIND_PROCESS_EXIT: u8 = 2;
pub const EVENT_KIND_NET_CONNECT: u8 = 3;
pub const EVENT_KIND_FILE_OPEN: u8 = 4;
pub const EVENT_KIND_FILE_RENAME: u8 = 5;
pub const EVENT_KIND_PRIVILEGE_CHANGE: u8 = 6;

pub const FILE_OP_OBSERVED: u8 = 0;
pub const FILE_OP_CREATE: u8 = 1;
pub const FILE_OP_WRITE: u8 = 2;
pub const FILE_OP_RENAME: u8 = 3;
pub const ID_NO_CHANGE: u32 = u32::MAX;

pub const PRIV_OP_SETUID: u8 = 1;
pub const PRIV_OP_SETEUID: u8 = 2;
pub const PRIV_OP_SETREUID: u8 = 3;
pub const PRIV_OP_SETRESUID: u8 = 4;
pub const PRIV_OP_SETGID: u8 = 5;
pub const PRIV_OP_SETEGID: u8 = 6;
pub const PRIV_OP_SETREGID: u8 = 7;
pub const PRIV_OP_SETRESGID: u8 = 8;
pub const PRIV_OP_CAPSET: u8 = 9;
pub const PRIV_OP_EXEC_COMMIT: u8 = 10;

pub const CAP_SUMMARY_SYS_ADMIN: u32 = 1 << 0;
pub const CAP_SUMMARY_NET_ADMIN: u32 = 1 << 1;
pub const CAP_SUMMARY_SYS_PTRACE: u32 = 1 << 2;
pub const CAP_SUMMARY_SYS_MODULE: u32 = 1 << 3;
pub const CAP_SUMMARY_SYS_RAWIO: u32 = 1 << 4;
pub const CAP_SUMMARY_SETUID: u32 = 1 << 5;
pub const CAP_SUMMARY_SETGID: u32 = 1 << 6;

pub const ADDR_FAMILY_UNSPEC: u16 = 0;
pub const ADDR_FAMILY_INET: u16 = 2;
pub const ADDR_FAMILY_INET6: u16 = 10;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TrailRawEvent {
    pub kind: u8,
    pub op: u8,
    pub protocol: u8,
    pub reserved: u8,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub aux_uid: u32,
    pub aux_gid: u32,
    pub flags: u32,
    pub result: i32,
    pub family: u16,
    pub port_be: u16,
    pub ts_ns: u64,
    pub comm: [u8; COMM_LEN],
    pub ip: [u8; IP_LEN],
    pub primary: [u8; PATH_LEN],
    pub secondary: [u8; PATH_LEN],
}

impl TrailRawEvent {
    pub const fn zeroed() -> Self {
        Self {
            kind: 0,
            op: 0,
            protocol: 0,
            reserved: 0,
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
            aux_uid: 0,
            aux_gid: 0,
            flags: 0,
            result: 0,
            family: 0,
            port_be: 0,
            ts_ns: 0,
            comm: [0; COMM_LEN],
            ip: [0; IP_LEN],
            primary: [0; PATH_LEN],
            secondary: [0; PATH_LEN],
        }
    }
}
