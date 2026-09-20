//! The heap of a process that lives for a few milliseconds.
//!
//! The C library's allocator hands memory back to the kernel the moment it is
//! free, which is the right policy for a daemon and the wrong one here: a
//! `run` was making forty-four `mmap` and thirty-seven `munmap` calls for a
//! few hundred kilobytes that were wanted again a moment later, one pair for
//! nearly every buffer that grew. Instead, allocations are carved from one
//! region that is never given back, and the C library's allocator takes over
//! only once the region is spent.
//!
//! Freed memory inside the region is not reused, so the most a command can
//! waste is what it allocated in total. The runtime allocates a few hundred
//! kilobytes per command, the region is sized well past that, and a command
//! that outgrows it falls back to the allocator it would otherwise have used.
//! The region lives in zero-initialised storage that the kernel backs with
//! pages only as they are touched, so an untouched remainder costs nothing.

use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::alloc::System;

/// Bytes the region holds.
const REGION_SIZE: usize = 1 << 20;

/// The region, aligned to a page so that its pages are its own.
#[repr(C, align(4096))]
struct Region(UnsafeCell<[u8; REGION_SIZE]>);

// SAFETY: the region is only ever handed out in disjoint ranges, each claimed
// by one winning compare-and-exchange on `NEXT`, so no two callers touch the
// same bytes through it.
unsafe impl Sync for Region {}

static REGION: Region = Region(UnsafeCell::new([0; REGION_SIZE]));

/// Offset of the first byte not yet handed out.
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// The allocator described above.
pub struct Heap;

impl Heap {
    /// Address of the region's first byte.
    fn base() -> usize {
        REGION.0.get().cast::<u8>() as usize
    }

    /// True when `ptr` was handed out of the region.
    fn holds(ptr: *mut u8) -> bool {
        let address = ptr as usize;
        address >= Self::base() && address < Self::base() + REGION_SIZE
    }

    /// Claims `layout` from the region, or answers null when it does not fit.
    fn claim(layout: Layout) -> *mut u8 {
        let base = Self::base();
        let mut current = NEXT.load(Ordering::Relaxed);
        // Bounded: each pass either claims the range or learns the offset
        // another claim moved, and a claim moves it at most once.
        for _ in 0..64u32 {
            let start = (base + current).next_multiple_of(layout.align());
            let end = start.wrapping_sub(base).saturating_add(layout.size());
            if end > REGION_SIZE {
                return core::ptr::null_mut();
            }
            match NEXT.compare_exchange_weak(
                current,
                end,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return start as *mut u8,
                Err(seen) => current = seen,
            }
        }
        core::ptr::null_mut()
    }
}

// Each entry point stays a call rather than being inlined into every
// allocation and drop site in the program, which the optimiser would
// otherwise do and which was measured to add tens of kilobytes to the binary
// that the sealed image then copies on every run.
//
// SAFETY: `claim` never hands out overlapping ranges, memory from the region
// is valid for the life of the process, and everything else is delegated to
// the system allocator, which upholds the contract for its own pointers.
unsafe impl GlobalAlloc for Heap {
    #[inline(never)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let claimed = Self::claim(layout);
        if claimed.is_null() {
            // SAFETY: the caller's layout is passed through unchanged.
            return unsafe { System.alloc(layout) };
        }
        claimed
    }

    #[inline(never)]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !Self::holds(ptr) {
            // SAFETY: a pointer outside the region came from the system
            // allocator with this same layout.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[inline(never)]
    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: Layout,
        new_size: usize,
    ) -> *mut u8 {
        if !Self::holds(ptr) {
            // SAFETY: as for `dealloc`.
            return unsafe { System.realloc(ptr, layout, new_size) };
        }
        // A buffer that is the most recent allocation grows in place, which a
        // `Vec` doubling itself nearly always is. Shrinking in place is always
        // fine.
        let offset = (ptr as usize).wrapping_sub(Self::base());
        let end = offset.saturating_add(layout.size());
        let wanted = offset.saturating_add(new_size);
        if new_size <= layout.size()
            || (wanted <= REGION_SIZE
                && NEXT
                    .compare_exchange(
                        end,
                        wanted,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok())
        {
            return ptr;
        }
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align())
        else {
            return core::ptr::null_mut();
        };
        // SAFETY: `new_layout` is a valid layout, and the copy covers only
        // bytes that both the old and the new allocation hold.
        unsafe {
            let moved = self.alloc(new_layout);
            if !moved.is_null() {
                core::ptr::copy_nonoverlapping(ptr, moved, layout.size());
            }
            moved
        }
    }
}
