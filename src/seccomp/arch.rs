//! Architectures a filter can cover, and the name to number resolution that
//! goes with each one.

use crate::seccomp::tables;

/// An architecture a seccomp filter can be built for.
///
/// The names match the `SCMP_ARCH_*` tokens the OCI configuration uses, minus
/// the prefix, so that parsing a configuration is a table lookup.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub enum Arch {
    /// 64-bit x86.
    X86_64,
    /// 32-bit x86.
    X86,
    /// The x32 ABI: 64-bit registers, 32-bit pointers.
    X32,
    /// 64-bit Arm.
    Aarch64,
    /// 32-bit Arm, EABI.
    Arm,
}

/// Every architecture this build can emit for.
pub const ALL: [Arch; 5] =
    [Arch::X86_64, Arch::X86, Arch::X32, Arch::Aarch64, Arch::Arm];

impl Arch {
    /// The architecture the runtime itself was built for.
    #[must_use]
    pub const fn native() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64
        }
    }

    /// Resolves a `SCMP_ARCH_*` token, with or without the prefix.
    #[must_use]
    pub fn by_name(name: &str) -> Option<Self> {
        let bare = name.strip_prefix("SCMP_ARCH_").unwrap_or(name);
        match bare.to_ascii_uppercase().as_str() {
            "X86_64" | "AMD64" => Some(Self::X86_64),
            "X86" | "I386" => Some(Self::X86),
            "X32" => Some(Self::X32),
            "AARCH64" | "ARM64" => Some(Self::Aarch64),
            "ARM" => Some(Self::Arm),
            _ => None,
        }
    }

    /// The `SCMP_ARCH_*` token for this architecture.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "SCMP_ARCH_X86_64",
            Self::X86 => "SCMP_ARCH_X86",
            Self::X32 => "SCMP_ARCH_X32",
            Self::Aarch64 => "SCMP_ARCH_AARCH64",
            Self::Arm => "SCMP_ARCH_ARM",
        }
    }

    /// The `AUDIT_ARCH_*` token a filter compares `seccomp_data.arch` against.
    ///
    /// x86-64 and x32 share a token: the kernel distinguishes them by bit 30
    /// of the syscall number, which the number tables already carry, so both
    /// can share one dispatch block.
    #[must_use]
    pub const fn audit_token(self) -> u32 {
        match self {
            Self::X86_64 | Self::X32 => 0xc000_003e,
            Self::X86 => 0x4000_0003,
            Self::Aarch64 => 0xc000_00b7,
            Self::Arm => 0x4000_0028,
        }
    }

    /// The syscall number column for this architecture.
    #[must_use]
    pub const fn numbers(self) -> &'static [i32; tables::COUNT] {
        match self {
            Self::X86_64 => &tables::X86_64,
            Self::X86 => &tables::X86,
            Self::X32 => &tables::X32,
            Self::Aarch64 => &tables::AARCH64,
            Self::Arm => &tables::ARM,
        }
    }

    /// The highest syscall number this architecture's table carries.
    ///
    /// Anything above it is a call the kernel gained after these tables were
    /// generated. That lets a filter answer for the two cases
    /// separately: a call the tables know and the profile did not name, and
    /// a call that did not exist when the profile was written.
    #[must_use]
    pub const fn highest_number(self) -> u32 {
        let numbers = self.numbers();
        let mut highest = 0;
        let mut index = 0;
        // Bounded by the table, whose length is fixed at compile time.
        while index < numbers.len() {
            // A column holds -1 where the architecture has no such call, and
            // the magnitude of a positive number is the number itself.
            let number = numbers[index];
            if number > 0 && number.unsigned_abs() > highest {
                highest = number.unsigned_abs();
            }
            index += 1;
        }
        highest
    }

    /// Resolves a syscall name to its number on this architecture.
    ///
    /// Returns `None` both for names this build has never heard of and for
    /// names the architecture does not implement. Callers distinguish the two
    /// with [`is_known_name`], because a profile naming a syscall that exists
    /// elsewhere is normal, while one naming a syscall that exists nowhere is
    /// usually a typo.
    #[must_use]
    pub fn syscall(self, name: &str) -> Option<u32> {
        let index = slot_of(name)?;
        let number = *self.numbers().get(index)?;
        (number != tables::ABSENT).then(|| number.unsigned_abs())
    }
}

/// Position of `name` in the shared table.
///
/// Resolving once and indexing every architecture column at that position is
/// what keeps emission cheap: a stock profile names several hundred syscalls,
/// and searching the table once per name rather than once per name and
/// architecture is the difference between microseconds and milliseconds.
#[must_use]
pub fn slot_of(name: &str) -> Option<usize> {
    tables::NAMES.binary_search(&name).ok()
}

/// True when any architecture implements `name`.
#[must_use]
pub fn is_known_name(name: &str) -> bool {
    slot_of(name).is_some()
}
