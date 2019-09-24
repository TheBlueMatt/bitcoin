use std::ffi::{c_void, CString};
use std::os::raw::{c_int, c_long};

extern "C" {
    pub fn rusty_IsInitialBlockDownload() -> bool;
    pub fn rusty_ShutdownRequested() -> bool;

    fn rusty_ProcessNewBlock(blockdata: *const u8, blockdatalen: usize, blockindex_requested: *const c_void);

    /// Connects count headers serialized in a block of memory, each stride bytes from each other.
    /// Returns the last header which was connected, if any (or NULL).
    fn rusty_ConnectHeaders(headers: *const u8, stride: usize, count: usize) -> *const c_void;

    // Utilities to work with CBlockIndex pointers. Wrapped in a safe wrapper below.

    /// Gets a CBlockIndex* pointer (casted to a c_void) representing the current tip.
    /// Guaranteed to never be NULL (but may be genesis)
    fn rusty_GetChainTip() -> *const c_void;

    /// Gets a CBlockIndex* pointer (casted to a c_void) representing the current best
    /// (not known to be invalid) header.
    /// Guaranteed to never be NULL (but may be genesis)
    fn rusty_GetBestHeader() -> *const c_void;

    /// Gets a CBlockIndex* pointer (casted to a c_void) representing the genesis block.
    /// Guaranteed to never be NULL
    fn rusty_GetGenesisIndex() -> *const c_void;

    /// Finds a CBlockIndex* for a given current height, or NULL if none is found
    fn rusty_HeightToIndex(height: i32) -> *const c_void;

    /// Gets the height of a given CBlockIndex* pointer
    fn rusty_IndexToHeight(index: *const c_void) -> i32;

    /// Gets the hash of a given CBlockIndex* pointer
    fn rusty_IndexToHash(index: *const c_void) -> *const u8;

    /// Serializes the header pointed to by the CBlockIndex* into eighty_bytes_dest.
    fn rusty_SerializeIndex(index: *const c_void, eighty_bytes_dest: *mut u8);
}

/// Connects the given array of (sorted, in chain order) headers (in serialized, 80-byte form).
/// Returns the last header which was connected, if any.
pub fn connect_headers_flat_bytes(headers: &[u8]) -> Option<BlockIndex> {
    if headers.len() % 80 != 0 { return None; }
    if headers.is_empty() { return None; }
    let index = unsafe { rusty_ConnectHeaders(headers.as_ptr(), 80, headers.len() / 80) };
    if index.is_null() { None } else { Some(BlockIndex { index }) }
}

/// Processes a new block, in serialized form.
/// blockindex_requested_by_state should be set *only* if the given BlockIndex was provided by
/// BlockProviderState::get_next_block_to_download(), and may be set to None always.
pub fn connect_block(blockdata: &[u8], blockindex_requested_by_state: Option<BlockIndex>) {
    let blockindex = match blockindex_requested_by_state { Some(index) => index.index, None => std::ptr::null(), };
    unsafe {
        rusty_ProcessNewBlock(blockdata.as_ptr(), blockdata.len(), blockindex);
    }
}

#[derive(PartialEq, Clone, Copy)]
pub struct BlockIndex {
    index: *const c_void,
}

impl BlockIndex {
    pub fn tip() -> Self {
        Self {
            index: unsafe { rusty_GetChainTip() },
        }
    }

    pub fn best_header() -> Self {
        Self {
            index: unsafe { rusty_GetBestHeader() },
        }
    }

    pub fn get_from_height(height: i32) -> Option<Self> {
        let index = unsafe { rusty_HeightToIndex(height) };
        if index.is_null() {
            None
        } else {
            Some(Self { index })
        }
    }

    pub fn genesis() -> Self {
        Self {
            index: unsafe { rusty_GetGenesisIndex() },
        }
    }

    pub fn height(&self) -> i32 {
        unsafe { rusty_IndexToHeight(self.index) }
    }

    pub fn hash(&self) -> [u8; 32] {
        let hashptr = unsafe { rusty_IndexToHash(self.index) };
        if hashptr.is_null() { unreachable!(); }
        let mut res = [0u8; 32];
        unsafe { std::ptr::copy(hashptr, res.as_mut_ptr(), 32) };
        res
    }

    /// Gets the hex formatted hash of this block, in byte-revered order (ie starting with the PoW
    /// 0s, as is commonly used in Bitcoin APIs).
    pub fn hash_hex(&self) -> String {
        let hash_bytes = self.hash();
        let mut res = String::with_capacity(64);
        for b in hash_bytes.iter().rev() {
            res.push(std::char::from_digit((b >> 4) as u32, 16).unwrap());
            res.push(std::char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        res
    }

    /// Gets the full, serialized, header
    pub fn header_bytes(&self) -> [u8; 80] {
        let mut ser = [0u8; 80];
        unsafe { rusty_SerializeIndex(self.index, (&mut ser).as_mut_ptr()); }
        ser
    }
}

extern "C" {
    // Utilities to work with BlockProviderState objects. Wrapped in a safe wrapper below.

    /// Creates a new BlockProviderState with a given current best CBlockIndex*.
    /// Don't forget to de-allocate!
    fn rusty_ProviderStateInit(blockindex: *const c_void) -> *mut c_void;
    /// De-allocates a BlockProviderState.
    fn rusty_ProviderStateFree(provider_state: *mut c_void);

    /// Sets the current best available CBlockIndex* for the given provider state.
    fn rusty_ProviderStateSetBest(provider_state: *mut c_void, blockindex: *const c_void);

    /// Gets the next CBlockIndex* a given provider should download, or NULL
    fn rusty_ProviderStateGetNextDownloads(providerindexvoid: *mut c_void, has_witness: bool) -> *const c_void;
}

pub struct BlockProviderState {
    // TODO: We should be smarter than to keep a copy of the current best pointer twice, but
    // crossing the FFI boundary just to look it up again sucks.
    current_best: BlockIndex,
    state: *mut c_void,
}
impl BlockProviderState {
    /// Initializes block provider state with a given current best header.
    /// Note that you can use a guess on the current best that moves backwards as you discover the
    /// providers' true chain state, though for efficiency you should try to avoid calling
    /// get_next_block_to_download in such a state.
    pub fn new_with_current_best(blockindex: BlockIndex) -> Self {
        Self {
            current_best: blockindex,
            state: unsafe { rusty_ProviderStateInit(blockindex.index) }
        }
    }

    /// Sets the current best available blockindex to the given one on this state.
    pub fn set_current_best(&mut self, blockindex: BlockIndex) {
        self.current_best = blockindex;
        unsafe { rusty_ProviderStateSetBest(self.state, blockindex.index) };
    }

    /// Gets the current best available blockindex as provided previously by set_current_best or
    /// new_with_current_best.
    pub fn get_current_best(&self) -> BlockIndex {
        self.current_best
    }

    /// Gets the BlockIndex representing the next block which should be downloaded, if any.
    pub fn get_next_block_to_download(&mut self, has_witness: bool) -> Option<BlockIndex> {
        let index = unsafe { rusty_ProviderStateGetNextDownloads(self.state, has_witness) };
        if index.is_null() { None } else { Some(BlockIndex { index }) }
    }
}
impl Drop for BlockProviderState {
    fn drop(&mut self) {
        unsafe { rusty_ProviderStateFree(self.state) };
    }
}

extern "C" {
    // General utilities. Wrapped in safe wrappers below.

    /// Provide some bytes of random(-ish) data for use in Bitcoin Core's RNG
    fn rusty_ProvideEntropy(data: *const u8, len: usize);

    /// Log some string
    fn rusty_LogLine(string: *const u8, debug: bool);
}

pub fn provide_entropy(data: &[u8]) {
    unsafe { rusty_ProvideEntropy(data.as_ptr(), data.len()); }
}

pub fn log_line(line: &str, debug: bool) {
    let cstr = match CString::new(line) {
        Ok(cstr) => cstr,
        Err(_) => CString::new("Attempted to log an str with nul bytes in it?!").unwrap(),
    };
    let ptr = cstr.as_bytes_with_nul();
    unsafe { rusty_LogLine(ptr.as_ptr(), debug); }
}

extern "C" {
    // Utilities related to transactions. Wrapped in safe wrappers below.

    /// Attempt to add a transaction to the memory pool
    fn rusty_AcceptToMemoryPool(txdata: *const u8, txdatalen: usize);
}

pub fn accept_to_memory_pool(data: &[u8]) {
    unsafe { rusty_AcceptToMemoryPool(data.as_ptr(), data.len()); }
}

extern "C" {
    // C syscall wrappers

    /// Sets a character device (open at the given fd) to raw, 115200 8N1
    pub fn rusty_set_char_dev_raw_115200(fd: c_int) -> bool;

    /// Waits for the given fd to be readable, or, optionally, writable.
    /// LSB indicates socket readable, second bit indicates socket writable (and await_write)
    pub fn rusty_select(fd: c_int, await_write: bool, timeout_sec: c_long, timeout_usec: c_long) -> u8;

    /// Returns true if the given file descriptor can be select()ed (ie is <= FD_SETSIZE)
    pub fn rusty_select_possible(fd: c_int) -> bool;
}
