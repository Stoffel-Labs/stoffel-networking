//! C Foreign Function Interface (FFI) for stoffel-networking
//!
//! This module provides a C-compatible API for interacting with stoffel-networking
//! from languages like C, Python, Go, JavaScript, etc. It allows external code to:
//!
//! - Create and manage tokio runtime instances
//! - Create and manage QUIC network managers
//! - Establish connections to peers
//! - Send and receive messages
//!
//! # Safety
//!
//! This module contains unsafe code due to the nature of FFI. Care must be taken when
//! using these functions from other languages to ensure memory safety and proper resource
//! management.
//!
//! # Thread Safety
//!
//! - All handle types use `Arc` internally for thread-safe sharing
//! - Callbacks may be invoked from any thread in the tokio runtime thread pool
//! - Thread-local error storage is used for error messages

use std::cell::RefCell;
use std::ffi::{c_char, c_void, CStr, CString};
use std::net::SocketAddr;
use std::os::raw::c_int;
use std::sync::Arc;

use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

use rustls::crypto::CryptoProvider;

use crate::network_utils::{Network, Node, SenderId};
use crate::transports::quic::{
    ConnectionState, QuicNetworkManager, QuicNode, PeerConnection,
};

// ============================================================================
// ERROR CODES
// ============================================================================

/// Operation completed successfully
pub const STOFFELNET_OK: c_int = 0;
/// Null pointer was passed where a valid pointer was expected
pub const STOFFELNET_ERR_NULL_POINTER: c_int = -1;
/// Invalid network address format
pub const STOFFELNET_ERR_INVALID_ADDRESS: c_int = -2;
/// Connection establishment failed
pub const STOFFELNET_ERR_CONNECTION: c_int = -3;
/// Send operation failed
pub const STOFFELNET_ERR_SEND: c_int = -4;
/// Receive operation failed
pub const STOFFELNET_ERR_RECEIVE: c_int = -5;
/// Operation timed out
pub const STOFFELNET_ERR_TIMEOUT: c_int = -6;
/// Party not found in network
pub const STOFFELNET_ERR_PARTY_NOT_FOUND: c_int = -7;
/// Runtime error occurred
pub const STOFFELNET_ERR_RUNTIME: c_int = -8;
/// Invalid UTF-8 string
pub const STOFFELNET_ERR_INVALID_UTF8: c_int = -9;
/// Operation cancelled
pub const STOFFELNET_ERR_CANCELLED: c_int = -10;

// ============================================================================
// CONNECTION STATE CONSTANTS
// ============================================================================

/// Connection is active and healthy
pub const STOFFELNET_STATE_CONNECTED: c_int = 0;
/// Connection is gracefully closing
pub const STOFFELNET_STATE_CLOSING: c_int = 1;
/// Connection has been closed
pub const STOFFELNET_STATE_CLOSED: c_int = 2;
/// Connection failed/disconnected unexpectedly
pub const STOFFELNET_STATE_DISCONNECTED: c_int = 3;

// ============================================================================
// THREAD-LOCAL ERROR STORAGE
// ============================================================================

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Sets the last error message for the current thread
fn set_last_error(err: impl ToString) {
    LAST_ERROR.with(|e| {
        let msg = CString::new(err.to_string()).unwrap_or_else(|_| {
            CString::new("Unknown error (invalid UTF-8)").unwrap()
        });
        *e.borrow_mut() = Some(msg);
    });
}

/// Gets the last error message for the current thread
///
/// # Returns
///
/// A pointer to a null-terminated C string containing the last error message,
/// or NULL if no error has been set.
///
/// # Safety
///
/// The returned pointer is valid until the next call to any FFI function
/// on the same thread. Do not free this pointer.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        e.borrow()
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null())
    })
}

/// Clears the last error message for the current thread
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_clear_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

// ============================================================================
// HANDLE TYPES
// ============================================================================

/// Wrapper for tokio runtime that can be shared across FFI boundary
pub struct RuntimeHandle {
    runtime: Runtime,
}

impl RuntimeHandle {
    /// Creates a new runtime handle
    pub fn new() -> Result<Self, String> {
        // Install the default crypto provider for rustls (required for QUIC/TLS)
        // This is safe to call multiple times - it will just return an error
        // if already installed, which we ignore.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let runtime = Runtime::new()
            .map_err(|e| format!("Failed to create tokio runtime: {}", e))?;
        Ok(Self { runtime })
    }

    /// Blocks on a future using this runtime
    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// Spawns a task on this runtime
    pub fn spawn<F>(&self, future: F) -> AbortHandle
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.runtime.spawn(future).abort_handle()
    }
}

/// Wrapper for network manager with runtime reference
pub struct NetworkManagerHandle {
    manager: Arc<Mutex<QuicNetworkManager>>,
    runtime: Arc<RuntimeHandle>,
}

/// Wrapper for peer connection
pub struct PeerConnectionHandle {
    connection: Arc<dyn PeerConnection>,
}

/// Wrapper for async operations that can be cancelled
pub struct AsyncOperationHandle {
    abort_handle: AbortHandle,
}

/// Wrapper for node
pub struct NodeHandle {
    node: QuicNode,
}

// ============================================================================
// OPAQUE POINTER TYPES
// ============================================================================

/// Opaque pointer to a tokio runtime
pub type StoffelRuntimeHandle = *mut c_void;

/// Opaque pointer to a network manager
pub type StoffelNetworkManagerHandle = *mut c_void;

/// Opaque pointer to a peer connection
pub type StoffelPeerConnectionHandle = *mut c_void;

/// Opaque pointer to an async operation
pub type StoffelAsyncOperationHandle = *mut c_void;

/// Opaque pointer to a node
pub type StoffelNodeHandle = *mut c_void;

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// Callback type for connection completion
pub type StoffelConnectCallback = Option<extern "C" fn(result: c_int, user_data: *mut c_void)>;

/// Callback type for receive completion
pub type StoffelReceiveCallback = Option<
    extern "C" fn(result: c_int, data: *const u8, len: usize, user_data: *mut c_void),
>;

/// Callback type for send completion
pub type StoffelSendCallback = Option<extern "C" fn(result: c_int, user_data: *mut c_void)>;

// ============================================================================
// RUNTIME MANAGEMENT
// ============================================================================

/// Creates a new tokio runtime for async operations
///
/// # Returns
///
/// A handle to the runtime, or NULL if creation failed.
/// Check `stoffelnet_last_error()` for error details.
///
/// # Safety
///
/// The returned handle must be freed with `stoffelnet_runtime_destroy` to avoid memory leaks.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_runtime_new() -> StoffelRuntimeHandle {
    match RuntimeHandle::new() {
        Ok(handle) => Box::into_raw(Box::new(handle)) as StoffelRuntimeHandle,
        Err(e) => {
            set_last_error(e);
            std::ptr::null_mut()
        }
    }
}

/// Destroys a tokio runtime
///
/// # Arguments
///
/// * `runtime` - Handle to the runtime to destroy
///
/// # Safety
///
/// The handle must not be used after this function is called.
/// Any async operations using this runtime should be cancelled first.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_runtime_destroy(runtime: StoffelRuntimeHandle) {
    if !runtime.is_null() {
        unsafe {
            let _ = Box::from_raw(runtime as *mut RuntimeHandle);
        }
    }
}

// ============================================================================
// NODE MANAGEMENT
// ============================================================================

/// Creates a new node with a specified party ID
///
/// # Arguments
///
/// * `address` - The network address as a null-terminated string (e.g., "127.0.0.1:9000")
/// * `party_id` - The party ID for this node
///
/// # Returns
///
/// A handle to the node, or NULL if creation failed.
///
/// # Safety
///
/// The address must be a valid null-terminated C string.
/// The returned handle must be freed with `stoffelnet_node_destroy`.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_node_new(
    address: *const c_char,
    party_id: u64,
) -> StoffelNodeHandle {
    if address.is_null() {
        set_last_error("Null address pointer");
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(address) };
    let address_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid UTF-8 in address");
            return std::ptr::null_mut();
        }
    };

    let socket_addr: SocketAddr = match address_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            set_last_error(format!("Invalid address format: {}", e));
            return std::ptr::null_mut();
        }
    };

    let node = QuicNode::from_party_id(SenderId::new(party_id as usize), socket_addr);
    Box::into_raw(Box::new(NodeHandle { node })) as StoffelNodeHandle
}

/// Creates a new node with a random UUID-based ID
///
/// # Arguments
///
/// * `address` - The network address as a null-terminated string
///
/// # Returns
///
/// A handle to the node, or NULL if creation failed.
///
/// # Safety
///
/// The address must be a valid null-terminated C string.
/// The returned handle must be freed with `stoffelnet_node_destroy`.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_node_new_random_id(address: *const c_char) -> StoffelNodeHandle {
    if address.is_null() {
        set_last_error("Null address pointer");
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(address) };
    let address_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid UTF-8 in address");
            return std::ptr::null_mut();
        }
    };

    let socket_addr: SocketAddr = match address_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            set_last_error(format!("Invalid address format: {}", e));
            return std::ptr::null_mut();
        }
    };

    let node = QuicNode::new_with_random_id(socket_addr);
    Box::into_raw(Box::new(NodeHandle { node })) as StoffelNodeHandle
}

/// Destroys a node handle
///
/// # Arguments
///
/// * `node` - Handle to the node to destroy
///
/// # Safety
///
/// The handle must not be used after this function is called.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_node_destroy(node: StoffelNodeHandle) {
    if !node.is_null() {
        unsafe {
            let _ = Box::from_raw(node as *mut NodeHandle);
        }
    }
}

/// Gets the address of a node as a string
///
/// # Arguments
///
/// * `node` - Handle to the node
///
/// # Returns
///
/// A newly allocated C string containing the address, or NULL on error.
/// The caller must free this string with `stoffelnet_free_string`.
///
/// # Safety
///
/// The node handle must be valid.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_node_address(node: StoffelNodeHandle) -> *mut c_char {
    if node.is_null() {
        set_last_error("Null node handle");
        return std::ptr::null_mut();
    }

    let handle = unsafe { &*(node as *const NodeHandle) };
    let address_str = handle.node.address().to_string();

    match CString::new(address_str) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => {
            set_last_error("Failed to create C string");
            std::ptr::null_mut()
        }
    }
}

/// Gets the party ID of a node
///
/// # Arguments
///
/// * `node` - Handle to the node
///
/// # Returns
///
/// The party ID of the node, or 0 if the handle is invalid.
///
/// # Safety
///
/// The node handle must be valid.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_node_party_id(node: StoffelNodeHandle) -> u64 {
    if node.is_null() {
        set_last_error("Null node handle");
        return 0;
    }

    let handle = unsafe { &*(node as *const NodeHandle) };
    handle.node.id().raw() as u64
}

// ============================================================================
// NETWORK MANAGER
// ============================================================================

/// Creates a new network manager
///
/// # Arguments
///
/// * `runtime` - Handle to the tokio runtime
/// * `bind_address` - The address to bind to for incoming connections (null-terminated string)
/// * `party_id` - The party ID for this node
///
/// # Returns
///
/// A handle to the network manager, or NULL if creation failed.
///
/// # Safety
///
/// - The runtime handle must be valid
/// - The bind_address must be a valid null-terminated C string
/// - The returned handle must be freed with `stoffelnet_manager_destroy`
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_manager_new(
    runtime: StoffelRuntimeHandle,
    bind_address: *const c_char,
    party_id: u64,
) -> StoffelNetworkManagerHandle {
    if runtime.is_null() {
        set_last_error("Null runtime handle");
        return std::ptr::null_mut();
    }

    if bind_address.is_null() {
        set_last_error("Null bind address");
        return std::ptr::null_mut();
    }

    let runtime_handle = unsafe { &*(runtime as *const RuntimeHandle) };

    let c_str = unsafe { CStr::from_ptr(bind_address) };
    let address_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid UTF-8 in bind address");
            return std::ptr::null_mut();
        }
    };

    let socket_addr: SocketAddr = match address_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            set_last_error(format!("Invalid bind address format: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Create the network manager with the specified party ID
    let mut manager = QuicNetworkManager::with_node_id(SenderId::new(party_id as usize));

    // Start listening on the bind address
    let result = runtime_handle.block_on(async {
        use crate::transports::quic::NetworkManager;
        manager.listen(socket_addr).await
    });

    if let Err(e) = result {
        set_last_error(format!("Failed to start listening: {}", e));
        return std::ptr::null_mut();
    }

    // Wrap in Arc for thread-safe sharing
    let runtime_arc = unsafe {
        // Create a new Arc from the raw pointer
        // We need to be careful here - we're creating a new Arc that doesn't own the data
        // This is safe because we're using the runtime reference, not taking ownership
        Arc::from_raw(runtime as *const RuntimeHandle)
    };
    // Immediately forget the Arc to prevent double-free
    let runtime_arc_clone = Arc::clone(&runtime_arc);
    std::mem::forget(runtime_arc);

    let handle = NetworkManagerHandle {
        manager: Arc::new(Mutex::new(manager)),
        runtime: runtime_arc_clone,
    };

    Box::into_raw(Box::new(handle)) as StoffelNetworkManagerHandle
}

/// Destroys a network manager
///
/// # Arguments
///
/// * `manager` - Handle to the network manager to destroy
///
/// # Safety
///
/// The handle must not be used after this function is called.
/// All connections should be closed before destroying the manager.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_manager_destroy(manager: StoffelNetworkManagerHandle) {
    if !manager.is_null() {
        unsafe {
            let _ = Box::from_raw(manager as *mut NetworkManagerHandle);
        }
    }
}

/// Adds a node to the network manager
///
/// # Arguments
///
/// * `manager` - Handle to the network manager
/// * `address` - The network address of the node (null-terminated string)
/// * `party_id` - The party ID of the node
///
/// # Returns
///
/// `STOFFELNET_OK` on success, or an error code on failure.
///
/// # Safety
///
/// - The manager handle must be valid
/// - The address must be a valid null-terminated C string
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_manager_add_node(
    manager: StoffelNetworkManagerHandle,
    address: *const c_char,
    party_id: u64,
) -> c_int {
    if manager.is_null() {
        set_last_error("Null manager handle");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    if address.is_null() {
        set_last_error("Null address");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    let handle = unsafe { &*(manager as *const NetworkManagerHandle) };

    let c_str = unsafe { CStr::from_ptr(address) };
    let address_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid UTF-8 in address");
            return STOFFELNET_ERR_INVALID_UTF8;
        }
    };

    let socket_addr: SocketAddr = match address_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            set_last_error(format!("Invalid address format: {}", e));
            return STOFFELNET_ERR_INVALID_ADDRESS;
        }
    };

    handle.runtime.block_on(async {
        let mut manager = handle.manager.lock().await;
        manager.add_node_with_party_id(SenderId::new(party_id as usize), socket_addr);
    });

    STOFFELNET_OK
}

/// Connects to a party (blocking)
///
/// # Arguments
///
/// * `manager` - Handle to the network manager
/// * `party_id` - The party ID to connect to
///
/// # Returns
///
/// `STOFFELNET_OK` on success, or an error code on failure.
///
/// # Safety
///
/// The manager handle must be valid.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_manager_connect_to_party(
    manager: StoffelNetworkManagerHandle,
    party_id: u64,
) -> c_int {
    if manager.is_null() {
        set_last_error("Null manager handle");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    let handle = unsafe { &*(manager as *const NetworkManagerHandle) };

    let result = handle.runtime.block_on(async {
        let mut manager = handle.manager.lock().await;

        // Find the node with this party_id
        let node_addr = manager
            .parties()
            .iter()
            .find(|n| n.id() == SenderId::new(party_id as usize))
            .map(|n| n.address());

        match node_addr {
            Some(addr) => manager.connect_as_server(addr).await,
            None => Err(format!("Party {} not found", party_id)),
        }
    });

    match result {
        Ok(_) => STOFFELNET_OK,
        Err(e) => {
            set_last_error(e);
            STOFFELNET_ERR_CONNECTION
        }
    }
}

/// Connects to a party asynchronously with a callback
///
/// # Arguments
///
/// * `manager` - Handle to the network manager
/// * `party_id` - The party ID to connect to
/// * `callback` - Callback function to invoke when connection completes
/// * `user_data` - User data to pass to the callback
///
/// # Returns
///
/// A handle to the async operation, or NULL if the operation could not be started.
///
/// # Safety
///
/// - The manager handle must be valid
/// - The callback may be invoked from any thread
/// - The user_data must remain valid until the callback is invoked
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_manager_connect_to_party_async(
    manager: StoffelNetworkManagerHandle,
    party_id: u64,
    callback: StoffelConnectCallback,
    user_data: *mut c_void,
) -> StoffelAsyncOperationHandle {
    if manager.is_null() {
        set_last_error("Null manager handle");
        return std::ptr::null_mut();
    }

    let handle = unsafe { &*(manager as *const NetworkManagerHandle) };
    let manager_arc = Arc::clone(&handle.manager);

    // Make user_data Send-safe
    let user_data = user_data as usize;

    let abort_handle = handle.runtime.spawn(async move {
        let result = {
            let mut manager = manager_arc.lock().await;

            // Find the node with this party_id
            let node_addr = manager
                .parties()
                .iter()
                .find(|n| n.id() == SenderId::new(party_id as usize))
                .map(|n| n.address());

            match node_addr {
                Some(addr) => manager.connect_as_server(addr).await,
                None => Err(format!("Party {} not found", party_id)),
            }
        };

        if let Some(cb) = callback {
            let code = match result {
                Ok(_) => STOFFELNET_OK,
                Err(e) => {
                    set_last_error(e);
                    STOFFELNET_ERR_CONNECTION
                }
            };
            cb(code, user_data as *mut c_void);
        }
    });

    Box::into_raw(Box::new(AsyncOperationHandle { abort_handle })) as StoffelAsyncOperationHandle
}

/// Accepts an incoming connection (blocking)
///
/// # Arguments
///
/// * `manager` - Handle to the network manager
/// * `out_party_id` - Pointer to store the connected party's ID
///
/// # Returns
///
/// `STOFFELNET_OK` on success, or an error code on failure.
///
/// # Safety
///
/// - The manager handle must be valid
/// - out_party_id must be a valid pointer
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_manager_accept_connection(
    manager: StoffelNetworkManagerHandle,
    out_party_id: *mut u64,
) -> c_int {
    if manager.is_null() {
        set_last_error("Null manager handle");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    if out_party_id.is_null() {
        set_last_error("Null out_party_id pointer");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    let handle = unsafe { &*(manager as *const NetworkManagerHandle) };

    let result = handle.runtime.block_on(async {
        use crate::transports::quic::NetworkManager;
        let mut manager = handle.manager.lock().await;
        manager.accept().await
    });

    match result {
        Ok(conn) => {
            // Try to determine the party ID from the connection
            // For now, we use the remote address to find the party
            let _remote_addr = conn.remote_address();

            // Since we don't have direct access to the party ID from the connection,
            // we'll set it to 0 as a placeholder. In practice, the handshake protocol
            // would have stored this information in the manager.
            unsafe {
                *out_party_id = 0;
            }

            STOFFELNET_OK
        }
        Err(e) => {
            set_last_error(e);
            STOFFELNET_ERR_CONNECTION
        }
    }
}

/// Gets a connection handle for a specific party
///
/// # Arguments
///
/// * `manager` - Handle to the network manager
/// * `party_id` - The party ID to get the connection for
///
/// # Returns
///
/// A handle to the connection, or NULL if no connection exists.
///
/// # Safety
///
/// - The manager handle must be valid
/// - The returned handle should not be freed (it shares ownership with the manager)
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_manager_get_connection(
    manager: StoffelNetworkManagerHandle,
    party_id: u64,
) -> StoffelPeerConnectionHandle {
    if manager.is_null() {
        set_last_error("Null manager handle");
        return std::ptr::null_mut();
    }

    let handle = unsafe { &*(manager as *const NetworkManagerHandle) };

    let conn = handle.runtime.block_on(async {
        let manager = handle.manager.lock().await;
        manager.get_connection(SenderId::new(party_id as usize)).await
    });

    match conn {
        Some(connection) => {
            let conn_handle = PeerConnectionHandle { connection };
            Box::into_raw(Box::new(conn_handle)) as StoffelPeerConnectionHandle
        }
        None => {
            set_last_error(format!("No connection to party {}", party_id));
            std::ptr::null_mut()
        }
    }
}

/// Checks if a party is connected
///
/// # Arguments
///
/// * `manager` - Handle to the network manager
/// * `party_id` - The party ID to check
///
/// # Returns
///
/// 1 if connected, 0 if not connected or on error.
///
/// # Safety
///
/// The manager handle must be valid.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_manager_is_party_connected(
    manager: StoffelNetworkManagerHandle,
    party_id: u64,
) -> c_int {
    if manager.is_null() {
        return 0;
    }

    let handle = unsafe { &*(manager as *const NetworkManagerHandle) };

    let is_connected = handle.runtime.block_on(async {
        let manager = handle.manager.lock().await;
        manager.is_party_connected(SenderId::new(party_id as usize)).await
    });

    if is_connected { 1 } else { 0 }
}

// ============================================================================
// PEER CONNECTION
// ============================================================================

/// Sends data on a connection (blocking)
///
/// # Arguments
///
/// * `conn` - Handle to the peer connection
/// * `runtime` - Handle to the tokio runtime
/// * `data` - Pointer to the data to send
/// * `data_len` - Length of the data in bytes
///
/// # Returns
///
/// `STOFFELNET_OK` on success, or an error code on failure.
///
/// # Safety
///
/// - The conn and runtime handles must be valid
/// - data must point to at least data_len bytes
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_connection_send(
    conn: StoffelPeerConnectionHandle,
    runtime: StoffelRuntimeHandle,
    data: *const u8,
    data_len: usize,
) -> c_int {
    if conn.is_null() {
        set_last_error("Null connection handle");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    if runtime.is_null() {
        set_last_error("Null runtime handle");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    if data.is_null() && data_len > 0 {
        set_last_error("Null data pointer with non-zero length");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    let conn_handle = unsafe { &*(conn as *const PeerConnectionHandle) };
    let runtime_handle = unsafe { &*(runtime as *const RuntimeHandle) };

    let bytes = if data_len > 0 {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    } else {
        &[]
    };

    let result = runtime_handle.block_on(async {
        conn_handle.connection.send(bytes).await
    });

    match result {
        Ok(_) => STOFFELNET_OK,
        Err(e) => {
            set_last_error(e);
            STOFFELNET_ERR_SEND
        }
    }
}

/// Receives data from a connection (blocking)
///
/// # Arguments
///
/// * `conn` - Handle to the peer connection
/// * `runtime` - Handle to the tokio runtime
/// * `out_data` - Pointer to store the received data pointer
/// * `out_len` - Pointer to store the received data length
///
/// # Returns
///
/// `STOFFELNET_OK` on success, or an error code on failure.
///
/// # Safety
///
/// - The conn and runtime handles must be valid
/// - out_data and out_len must be valid pointers
/// - The caller must free the received data with `stoffelnet_free_bytes`
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_connection_receive(
    conn: StoffelPeerConnectionHandle,
    runtime: StoffelRuntimeHandle,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    if conn.is_null() {
        set_last_error("Null connection handle");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    if runtime.is_null() {
        set_last_error("Null runtime handle");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    if out_data.is_null() || out_len.is_null() {
        set_last_error("Null output pointer");
        return STOFFELNET_ERR_NULL_POINTER;
    }

    let conn_handle = unsafe { &*(conn as *const PeerConnectionHandle) };
    let runtime_handle = unsafe { &*(runtime as *const RuntimeHandle) };

    let result = runtime_handle.block_on(async {
        conn_handle.connection.receive().await
    });

    match result {
        Ok(data) => {
            let len = data.len();
            let ptr = if len > 0 {
                let mut boxed = data.into_boxed_slice();
                let ptr = boxed.as_mut_ptr();
                std::mem::forget(boxed);
                ptr
            } else {
                std::ptr::null_mut()
            };

            unsafe {
                *out_data = ptr;
                *out_len = len;
            }
            STOFFELNET_OK
        }
        Err(e) => {
            set_last_error(e);
            unsafe {
                *out_data = std::ptr::null_mut();
                *out_len = 0;
            }
            STOFFELNET_ERR_RECEIVE
        }
    }
}

/// Sends data asynchronously with a callback
///
/// # Arguments
///
/// * `conn` - Handle to the peer connection
/// * `runtime` - Handle to the tokio runtime
/// * `data` - Pointer to the data to send
/// * `data_len` - Length of the data in bytes
/// * `callback` - Callback function to invoke when send completes
/// * `user_data` - User data to pass to the callback
///
/// # Returns
///
/// A handle to the async operation, or NULL on error.
///
/// # Safety
///
/// - All handles must be valid
/// - data must point to at least data_len bytes (data is copied)
/// - The callback may be invoked from any thread
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_connection_send_async(
    conn: StoffelPeerConnectionHandle,
    runtime: StoffelRuntimeHandle,
    data: *const u8,
    data_len: usize,
    callback: StoffelSendCallback,
    user_data: *mut c_void,
) -> StoffelAsyncOperationHandle {
    if conn.is_null() || runtime.is_null() {
        set_last_error("Null handle");
        return std::ptr::null_mut();
    }

    if data.is_null() && data_len > 0 {
        set_last_error("Null data pointer with non-zero length");
        return std::ptr::null_mut();
    }

    let conn_handle = unsafe { &*(conn as *const PeerConnectionHandle) };
    let runtime_handle = unsafe { &*(runtime as *const RuntimeHandle) };

    // Copy data to owned Vec
    let owned_data = if data_len > 0 {
        unsafe { std::slice::from_raw_parts(data, data_len).to_vec() }
    } else {
        Vec::new()
    };

    let connection = Arc::clone(&conn_handle.connection);
    let user_data = user_data as usize;

    let abort_handle = runtime_handle.spawn(async move {
        let result = connection.send(&owned_data).await;

        if let Some(cb) = callback {
            let code = match result {
                Ok(_) => STOFFELNET_OK,
                Err(e) => {
                    set_last_error(e);
                    STOFFELNET_ERR_SEND
                }
            };
            cb(code, user_data as *mut c_void);
        }
    });

    Box::into_raw(Box::new(AsyncOperationHandle { abort_handle })) as StoffelAsyncOperationHandle
}

/// Receives data asynchronously with a callback
///
/// # Arguments
///
/// * `conn` - Handle to the peer connection
/// * `runtime` - Handle to the tokio runtime
/// * `callback` - Callback function to invoke when receive completes
/// * `user_data` - User data to pass to the callback
///
/// # Returns
///
/// A handle to the async operation, or NULL on error.
///
/// # Safety
///
/// - All handles must be valid
/// - The callback may be invoked from any thread
/// - The data pointer in the callback is only valid during the callback
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_connection_receive_async(
    conn: StoffelPeerConnectionHandle,
    runtime: StoffelRuntimeHandle,
    callback: StoffelReceiveCallback,
    user_data: *mut c_void,
) -> StoffelAsyncOperationHandle {
    if conn.is_null() || runtime.is_null() {
        set_last_error("Null handle");
        return std::ptr::null_mut();
    }

    let conn_handle = unsafe { &*(conn as *const PeerConnectionHandle) };
    let runtime_handle = unsafe { &*(runtime as *const RuntimeHandle) };

    let connection = Arc::clone(&conn_handle.connection);
    let user_data = user_data as usize;

    let abort_handle = runtime_handle.spawn(async move {
        let result = connection.receive().await;

        if let Some(cb) = callback {
            match result {
                Ok(data) => {
                    cb(STOFFELNET_OK, data.as_ptr(), data.len(), user_data as *mut c_void);
                }
                Err(e) => {
                    set_last_error(e);
                    cb(STOFFELNET_ERR_RECEIVE, std::ptr::null(), 0, user_data as *mut c_void);
                }
            }
        }
    });

    Box::into_raw(Box::new(AsyncOperationHandle { abort_handle })) as StoffelAsyncOperationHandle
}

/// Cancels an async operation
///
/// # Arguments
///
/// * `op` - Handle to the async operation
///
/// # Returns
///
/// `STOFFELNET_OK` on success.
///
/// # Safety
///
/// The operation handle must be valid and will be invalidated after this call.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_async_cancel(op: StoffelAsyncOperationHandle) -> c_int {
    if op.is_null() {
        return STOFFELNET_OK; // Already cancelled or never started
    }

    let handle = unsafe { Box::from_raw(op as *mut AsyncOperationHandle) };
    handle.abort_handle.abort();

    STOFFELNET_OK
}

/// Gets the connection state
///
/// # Arguments
///
/// * `conn` - Handle to the peer connection
/// * `runtime` - Handle to the tokio runtime
///
/// # Returns
///
/// One of the STOFFELNET_STATE_* constants, or -1 on error.
///
/// # Safety
///
/// Both handles must be valid.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_connection_state(
    conn: StoffelPeerConnectionHandle,
    runtime: StoffelRuntimeHandle,
) -> c_int {
    if conn.is_null() || runtime.is_null() {
        return -1;
    }

    let conn_handle = unsafe { &*(conn as *const PeerConnectionHandle) };
    let runtime_handle = unsafe { &*(runtime as *const RuntimeHandle) };

    let state = runtime_handle.block_on(async {
        conn_handle.connection.state().await
    });

    match state {
        ConnectionState::Connected => STOFFELNET_STATE_CONNECTED,
        ConnectionState::Closing => STOFFELNET_STATE_CLOSING,
        ConnectionState::Closed => STOFFELNET_STATE_CLOSED,
        ConnectionState::Disconnected => STOFFELNET_STATE_DISCONNECTED,
    }
}

/// Checks if a connection is alive
///
/// # Arguments
///
/// * `conn` - Handle to the peer connection
/// * `runtime` - Handle to the tokio runtime
///
/// # Returns
///
/// 1 if connected, 0 if not connected or on error.
///
/// # Safety
///
/// Both handles must be valid.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_connection_is_connected(
    conn: StoffelPeerConnectionHandle,
    runtime: StoffelRuntimeHandle,
) -> c_int {
    if conn.is_null() || runtime.is_null() {
        return 0;
    }

    let conn_handle = unsafe { &*(conn as *const PeerConnectionHandle) };
    let runtime_handle = unsafe { &*(runtime as *const RuntimeHandle) };

    let is_connected = runtime_handle.block_on(async {
        conn_handle.connection.is_connected().await
    });

    if is_connected { 1 } else { 0 }
}

/// Closes a connection
///
/// # Arguments
///
/// * `conn` - Handle to the peer connection
/// * `runtime` - Handle to the tokio runtime
///
/// # Safety
///
/// Both handles must be valid.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_connection_close(
    conn: StoffelPeerConnectionHandle,
    runtime: StoffelRuntimeHandle,
) {
    if conn.is_null() || runtime.is_null() {
        return;
    }

    let conn_handle = unsafe { &*(conn as *const PeerConnectionHandle) };
    let runtime_handle = unsafe { &*(runtime as *const RuntimeHandle) };

    let _ = runtime_handle.block_on(async {
        conn_handle.connection.close().await
    });
}

/// Destroys a connection handle
///
/// # Arguments
///
/// * `conn` - Handle to the peer connection
///
/// # Safety
///
/// The handle must not be used after this function is called.
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_connection_destroy(conn: StoffelPeerConnectionHandle) {
    if !conn.is_null() {
        unsafe {
            let _ = Box::from_raw(conn as *mut PeerConnectionHandle);
        }
    }
}

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

/// Frees a byte buffer allocated by stoffel-networking
///
/// # Arguments
///
/// * `data` - Pointer to the data to free
/// * `len` - Length of the data in bytes
///
/// # Safety
///
/// - data must have been allocated by a stoffel-networking function
/// - The pointer must not be used after this function is called
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_free_bytes(data: *mut u8, len: usize) {
    if !data.is_null() && len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(data, len, len);
        }
    }
}

/// Frees a string allocated by stoffel-networking
///
/// # Arguments
///
/// * `str` - Pointer to the string to free
///
/// # Safety
///
/// - str must have been allocated by a stoffel-networking function
/// - The pointer must not be used after this function is called
#[unsafe(no_mangle)]
pub extern "C" fn stoffelnet_free_string(str: *mut c_char) {
    if !str.is_null() {
        unsafe {
            let _ = CString::from_raw(str);
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_handling() {
        set_last_error("Test error");
        let error = stoffelnet_last_error();
        assert!(!error.is_null());

        let c_str = unsafe { CStr::from_ptr(error) };
        assert_eq!(c_str.to_str().unwrap(), "Test error");

        stoffelnet_clear_error();
        let error = stoffelnet_last_error();
        assert!(error.is_null());
    }

    #[test]
    fn test_runtime_lifecycle() {
        let runtime = stoffelnet_runtime_new();
        assert!(!runtime.is_null());

        stoffelnet_runtime_destroy(runtime);
    }

    #[test]
    fn test_node_lifecycle() {
        let addr = CString::new("127.0.0.1:9000").unwrap();
        let node = stoffelnet_node_new(addr.as_ptr(), 42);
        assert!(!node.is_null());

        let party_id = stoffelnet_node_party_id(node);
        assert_eq!(party_id, 42);

        let address = stoffelnet_node_address(node);
        assert!(!address.is_null());
        stoffelnet_free_string(address);

        stoffelnet_node_destroy(node);
    }

    #[test]
    fn test_node_random_id() {
        let addr = CString::new("127.0.0.1:9001").unwrap();
        let node = stoffelnet_node_new_random_id(addr.as_ptr());
        assert!(!node.is_null());

        let party_id = stoffelnet_node_party_id(node);
        assert!(party_id > 0); // Random UUID should produce non-zero ID

        stoffelnet_node_destroy(node);
    }

    #[test]
    fn test_null_handling() {
        // Test that null handles are handled gracefully
        assert_eq!(stoffelnet_manager_add_node(std::ptr::null_mut(), std::ptr::null(), 0), STOFFELNET_ERR_NULL_POINTER);
        assert_eq!(stoffelnet_manager_connect_to_party(std::ptr::null_mut(), 0), STOFFELNET_ERR_NULL_POINTER);
        assert!(stoffelnet_manager_get_connection(std::ptr::null_mut(), 0).is_null());
        assert_eq!(stoffelnet_manager_is_party_connected(std::ptr::null_mut(), 0), 0);

        stoffelnet_runtime_destroy(std::ptr::null_mut()); // Should not crash
        stoffelnet_manager_destroy(std::ptr::null_mut()); // Should not crash
        stoffelnet_node_destroy(std::ptr::null_mut()); // Should not crash
        stoffelnet_connection_destroy(std::ptr::null_mut()); // Should not crash
    }
}
