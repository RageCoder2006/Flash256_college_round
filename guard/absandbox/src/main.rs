//! absandbox: run one command under Landlock (filesystem + TCP connect allow-list),
//! a seccomp denylist, rlimits and no_new_privs. Needs no root and no user namespaces.
//!
//!   absandbox --workspace DIR [--ro PATH]... [--connect-port N]... [--cpu S] [--mem MB]
//!             [--nproc N] [--fsize MB] -- CMD ARGS...
//!
//! The workspace is the only writable tree. TCP connects are denied except to the listed ports
//! (the canary sink), so every escape attempt either fails with EACCES or lands on the sink.
use landlock::{
    Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

struct Opts {
    workspace: String,
    ro: Vec<String>,
    ports: Vec<u16>,
    cpu: u64,
    mem_mb: u64,
    nproc: u64,
    fsize_mb: u64,
    cmd: Vec<String>,
}

fn die(msg: &str) -> ! {
    eprintln!("absandbox: {msg}");
    exit(125);
}

fn parse() -> Opts {
    let mut o = Opts { workspace: String::new(), ro: vec![], ports: vec![], cpu: 20, mem_mb: 1024, nproc: 64, fsize_mb: 64, cmd: vec![] };
    let mut a = std::env::args().skip(1);
    while let Some(x) = a.next() {
        let mut val = |n: &str| a.next().unwrap_or_else(|| die(&format!("{n} needs a value")));
        match x.as_str() {
            "--workspace" => o.workspace = val("--workspace"),
            "--ro" => o.ro.push(val("--ro")),
            "--connect-port" => o.ports.push(val("--connect-port").parse().unwrap_or_else(|_| die("bad port"))),
            "--cpu" => o.cpu = val("--cpu").parse().unwrap_or_else(|_| die("bad --cpu")),
            "--mem" => o.mem_mb = val("--mem").parse().unwrap_or_else(|_| die("bad --mem")),
            "--nproc" => o.nproc = val("--nproc").parse().unwrap_or_else(|_| die("bad --nproc")),
            "--fsize" => o.fsize_mb = val("--fsize").parse().unwrap_or_else(|_| die("bad --fsize")),
            "--" => {
                o.cmd = a.by_ref().collect();
                break;
            }
            other => die(&format!("unknown flag {other}")),
        }
    }
    if o.workspace.is_empty() || o.cmd.is_empty() {
        die("usage: absandbox --workspace DIR [--ro PATH]... [--connect-port N]... -- CMD ARGS...");
    }
    o
}

/// RLIMIT_NPROC is per real UID across the whole machine and counts threads, so the cap must sit
/// above the tasks the user already runs: current thread count + the sandbox's own allowance.
fn user_tasks() -> u64 {
    let uid = unsafe { libc::getuid() }.to_string();
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            if !e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let Ok(st) = std::fs::read_to_string(e.path().join("status")) else { continue };
            let mut mine = false;
            let mut threads = 0u64;
            for l in st.lines() {
                if let Some(v) = l.strip_prefix("Uid:") {
                    mine = v.split_whitespace().next() == Some(uid.as_str());
                } else if let Some(v) = l.strip_prefix("Threads:") {
                    threads = v.trim().parse().unwrap_or(0);
                }
            }
            if mine {
                n += threads;
            }
        }
    }
    n
}

fn rlimit(res: libc::__rlimit_resource_t, v: u64) {
    let l = libc::rlimit { rlim_cur: v, rlim_max: v };
    if unsafe { libc::setrlimit(res, &l) } != 0 {
        die("setrlimit failed");
    }
}

fn landlock(o: &Opts) {
    let abi = ABI::V4; // fs + tcp connect/bind; BestEffort degrades on older kernels
    let fs_all = AccessFs::from_all(abi);
    let fs_read = AccessFs::from_read(abi);
    let mut rs = Ruleset::default()
        .handle_access(fs_all)
        .and_then(|r| r.handle_access(AccessNet::from_all(abi)))
        .and_then(|r| r.create())
        .unwrap_or_else(|e| die(&format!("landlock ruleset: {e}")));
    let mut ro: Vec<&str> = vec!["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/dev", "/proc/self"];
    for p in &o.ro {
        ro.push(p);
    }
    for p in ro {
        if let Ok(fd) = PathFd::new(p) {
            rs = rs.add_rule(PathBeneath::new(fd, fs_read)).unwrap_or_else(|e| die(&format!("landlock ro {p}: {e}")));
        }
    }
    // /dev/null and /dev/tty must be writable for ordinary shell redirection.
    for p in ["/dev/null", "/dev/zero"] {
        if let Ok(fd) = PathFd::new(p) {
            rs = rs.add_rule(PathBeneath::new(fd, fs_all)).unwrap_or_else(|e| die(&format!("landlock {p}: {e}")));
        }
    }
    let ws = PathFd::new(&o.workspace).unwrap_or_else(|e| die(&format!("workspace {}: {e}", o.workspace)));
    rs = rs.add_rule(PathBeneath::new(ws, fs_all)).unwrap_or_else(|e| die(&format!("landlock workspace: {e}")));
    for port in &o.ports {
        rs = rs.add_rule(NetPort::new(*port, AccessNet::ConnectTcp)).unwrap_or_else(|e| die(&format!("landlock net: {e}")));
    }
    // No bind rules: the sandboxed process cannot listen on TCP.
    rs.restrict_self().unwrap_or_else(|e| die(&format!("landlock restrict: {e}")));
}

fn seccomp() {
    use SeccompCmpArgLen::*;
    use SeccompCmpOp::*;
    let deny: Vec<i64> = vec![
        libc::SYS_ptrace, libc::SYS_mount, libc::SYS_umount2, libc::SYS_pivot_root, libc::SYS_setns, libc::SYS_unshare,
        libc::SYS_bpf, libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key, libc::SYS_kexec_load,
        libc::SYS_init_module, libc::SYS_finit_module, libc::SYS_delete_module, libc::SYS_reboot,
        libc::SYS_swapon, libc::SYS_swapoff, libc::SYS_perf_event_open, libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev, libc::SYS_userfaultfd, libc::SYS_chroot, libc::SYS_acct,
    ];
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for s in deny {
        rules.insert(s, vec![]); // empty rule list = match unconditionally
    }
    // Block UDP/raw/packet sockets (Landlock only governs TCP): DNS and datagram exfil.
    let sock = |dom: i32, ty: Option<u64>| {
        let mut c = vec![SeccompCondition::new(0, Dword, Eq, dom as u64).unwrap()];
        if let Some(t) = ty {
            c.push(SeccompCondition::new(1, Dword, MaskedEq(0xf), t).unwrap());
        }
        SeccompRule::new(c).unwrap()
    };
    rules.insert(
        libc::SYS_socket,
        vec![
            sock(libc::AF_INET, Some(libc::SOCK_DGRAM as u64)),
            sock(libc::AF_INET, Some(libc::SOCK_RAW as u64)),
            sock(libc::AF_INET6, Some(libc::SOCK_DGRAM as u64)),
            sock(libc::AF_INET6, Some(libc::SOCK_RAW as u64)),
            sock(libc::AF_PACKET, None),
        ],
    );
    let arch = std::env::consts::ARCH.try_into().unwrap_or_else(|_| die("unsupported arch"));
    let filter: BpfProgram = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch)
        .and_then(|f| f.try_into())
        .unwrap_or_else(|e| die(&format!("seccomp build: {e}")));
    apply_filter(&filter).unwrap_or_else(|e| die(&format!("seccomp apply: {e}")));
}

fn main() {
    let o = parse();
    rlimit(libc::RLIMIT_CPU, o.cpu);
    rlimit(libc::RLIMIT_AS, o.mem_mb * 1024 * 1024);
    rlimit(libc::RLIMIT_NPROC, user_tasks() + o.nproc);
    rlimit(libc::RLIMIT_FSIZE, o.fsize_mb * 1024 * 1024);
    rlimit(libc::RLIMIT_CORE, 0);
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        die("no_new_privs failed");
    }
    landlock(&o);
    seccomp();
    std::env::set_current_dir(&o.workspace).unwrap_or_else(|e| die(&format!("chdir: {e}")));
    let err = Command::new(&o.cmd[0]).args(&o.cmd[1..]).env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin").env("HOME", &o.workspace).env("TMPDIR", &o.workspace)
        .exec();
    die(&format!("exec {}: {err}", o.cmd[0]));
}
