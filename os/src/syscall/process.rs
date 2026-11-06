//! Process management syscalls
use crate::{mm::{MapPermission, PageTable, PhysAddr, VirtAddr, VirtPageNum}, task::{change_program_brk, current_user_token, exit_current_and_run_next, get_current_task_syscall_count, insert_framed_area_into_current_task, suspend_current_and_run_next}, timer::get_time_us};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let page_table = PageTable::from_token(current_user_token());
    let va = VirtAddr::from(ts as usize);
    let pte = page_table.translate(va.floor()).unwrap();

    let us = get_time_us();
    unsafe {
        let pa = PhysAddr::from(pte.ppn()).0 + va.page_offset();
        let data = pa as *mut TimeVal;
        *data = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    if trace_request == 0 || trace_request == 1 {
        let page_table = PageTable::from_token(current_user_token());
        let va = VirtAddr::from(id);
        if va.0 != id {
            return -1;
        }
        let pte = match page_table.translate(va.floor()) {
            Some(v) => v,
            None => return -1,
        };

        if trace_request == 0 {
            if !pte.is_valid() || !pte.readable() {
                return -1;
            }

            let pa = PhysAddr::from(pte.ppn()).0 + va.page_offset();
            let id = pa as *const u8;
            unsafe {id.read() as isize}
        } else {
            if !pte.is_valid() || !pte.writable() {
                return -1;
            }

            let pa = PhysAddr::from(pte.ppn()).0 + va.page_offset();
            let id = pa as *mut u8;
            unsafe {id.write(data as u8);}
            0
        }
    } else if trace_request == 2 {
        get_current_task_syscall_count(id) as isize
    } else {
        -1
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    let va = VirtAddr::from(start);
    if !va.aligned() || port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }

    // 查找 [start, start + len) 中是否存在已经被映射的页
    let page_table = PageTable::from_token(current_user_token());
    let vpn_start = VirtPageNum::from(va);
    let vpn_end = VirtPageNum::from(VirtAddr::from(start + len).ceil());
    for v in vpn_start.0..vpn_end.0 {
        let vpn = VirtPageNum::from(v);
        if let Some(pte) = page_table.translate(vpn) {
            if pte.is_valid() {
                return -1;
            }
        }
    }
    
    let mut permission = MapPermission::U;
    if (port >> 0) & 1 == 1 {
        permission |= MapPermission::R;
    }
    if (port >> 1) & 1 == 1 {
        permission |= MapPermission::W;
    }
    if (port >> 2) & 1 == 1 {
        permission |= MapPermission::X;
    }
    
    insert_framed_area_into_current_task(vpn_start.into(), vpn_end.into(), permission);
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    let va = VirtAddr::from(start);
    if !va.aligned() {
        return -1;
    }

    let mut page_table = PageTable::from_token(current_user_token());
    let vpn_start = VirtPageNum::from(va);
    let vpn_end = VirtPageNum::from(VirtAddr::from(start + len).ceil());
    for v in vpn_start.0..vpn_end.0 {
        let vpn = VirtPageNum::from(v);
        if let Some(pte) = page_table.translate(vpn) {
            if pte.is_valid() {
                page_table.unmap(vpn);
            } else {
                return -1;
            }
        } else {
            return -1;
        }
    }
    0
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
