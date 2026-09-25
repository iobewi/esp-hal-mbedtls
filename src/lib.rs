#![no_std]

//! Small integration layer between `esp-hal` and `mbedtls-rs`.
//!
//! The crate owns reusable transport mechanics only:
//!
//! - adapts the ESP hardware RNG to `rand_core::TryCryptoRng`;
//! - installs MbedTLS monotonic and wall-clock hooks;
//! - owns the single global `mbedtls_rs::Tls` instance;
//! - validates certificate/private-key pairs;
//! - builds server TLS configurations from PEM;
//! - optionally performs DNS/TCP/TLS client connection over `embassy-net`;
//! - optionally adapts a connected TLS session to a picoserve socket.
//!
//! It deliberately does not own certificate persistence, application NVS
//! layout, SNTP policy, HTTP routes, or reconnect orchestration.

extern crate alloc;

pub use mbedtls_rs;

use alloc::ffi::CString;
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use alloc::boxed::Box;
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use core::convert::Infallible;
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use esp_hal::rng::Rng;
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use rand_core::{TryCryptoRng, TryRng};
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use static_cell::StaticCell;
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use mbedtls_rs::sys::hook::timer::{hook_timer, MbedtlsTimer};
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use mbedtls_rs::sys::hook::wall_clock::{hook_wall_clock, MbedtlsWallClock};
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use mbedtls_rs::sys::mbedtls_ms_time_t;
use mbedtls_rs::sys::tm;
use mbedtls_rs::{Certificate, Credentials, PrivateKey, ServerSessionConfig, SessionConfig, TlsReference, X509};
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
use mbedtls_rs::Tls;

/// Function used by MbedTLS to obtain Unix epoch seconds.
///
/// Returning `None` makes certificate-date validation fail closed.
pub type UnixTimeFn = fn() -> Option<u64>;

/// ESP hardware RNG adapter carrying the cryptographic RNG marker required by
/// `mbedtls-rs`.
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
pub struct EspCryptoRng(Rng);

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
impl EspCryptoRng {
    pub fn new() -> Self {
        Self(Rng::new())
    }
}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
impl Default for EspCryptoRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
impl TryRng for EspCryptoRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.random())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.0.read(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read(dst);
        Ok(())
    }
}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
impl TryCryptoRng for EspCryptoRng {}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
struct WallClock {
    now: UnixTimeFn,
}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
impl MbedtlsWallClock for WallClock {
    fn instant(&self) -> Option<tm> {
        epoch_to_tm((self.now)()?)
    }
}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
struct UptimeTimer;

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
impl MbedtlsTimer for UptimeTimer {
    fn now(&self) -> mbedtls_ms_time_t {
        embassy_time::Instant::now().as_millis() as mbedtls_ms_time_t
    }
}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
static TIMER: UptimeTimer = UptimeTimer;
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
static WALL_CLOCK: StaticCell<WallClock> = StaticCell::new();
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
static RNG: StaticCell<EspCryptoRng> = StaticCell::new();
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
static TLS: StaticCell<Tls<'static>> = StaticCell::new();

/// Named alias convenient for long-lived application structs.
pub type TlsReferenceStatic = TlsReference<'static>;

/// Initializes the process-global MbedTLS instance.
///
/// This must be called exactly once, before any MbedTLS session is created.
/// `now` may return `None` until the application has synchronized its wall
/// clock; X.509 validity checks then fail closed.
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
pub fn init(now: UnixTimeFn) -> TlsReferenceStatic {
    let wall_clock = WALL_CLOCK.init(WallClock { now });

    // SAFETY: both hooks receive process-lifetime statics and are installed
    // before the first MbedTLS X.509/session use.
    unsafe {
        hook_timer(Some(&TIMER));
        hook_wall_clock(Some(wall_clock));
    }

    let rng = RNG.init(EspCryptoRng::new());
    let tls = TLS.init(Tls::new(rng).expect("esp-hal-mbedtls::init() called more than once"));
    tls.reference()
}

/// Unix epoch seconds -> MbedTLS broken-down UTC time.
///
/// Kept public mostly for deterministic host-side verification by consumers.
pub fn epoch_to_tm(epoch: u64) -> Option<tm> {
    let days = i64::try_from(epoch / 86_400).ok()?;
    let secs = (epoch % 86_400) as i32;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as i32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as i32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    const CUMULATIVE: [i32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let yday = CUMULATIVE[(month - 1) as usize] + day - 1 + i32::from(is_leap && month > 2);

    Some(tm {
        tm_sec: secs % 60,
        tm_min: secs / 60 % 60,
        tm_hour: secs / 3_600,
        tm_mday: day,
        tm_mon: month - 1,
        tm_year: (year - 1900) as i32,
        tm_wday: ((days + 4).rem_euclid(7)) as i32,
        tm_yday: yday,
        tm_isdst: 0,
    })
}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
unsafe extern "C" fn mbedtls_rng(
    _ctx: *mut core::ffi::c_void,
    out: *mut u8,
    len: usize,
) -> core::ffi::c_int {
    // SAFETY: MbedTLS provides a writable buffer of exactly `len` bytes.
    Rng::new().read(unsafe { core::slice::from_raw_parts_mut(out, len) });
    0
}

/// Certificate/private-key validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
    InvalidCertificate,
    InvalidPrivateKey,
    Mismatch,
}

/// Parses the leaf certificate and private key and verifies that they form a
/// pair. No persistence is performed.
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
pub fn validate_cert_key_pair(cert_pem: &str, key_pem: &str) -> Result<(), PairError> {
    use mbedtls_rs::sys::{
        mbedtls_pk_check_pair, mbedtls_pk_context, mbedtls_pk_free, mbedtls_pk_init, mbedtls_pk_parse_key,
        mbedtls_x509_crt, mbedtls_x509_crt_free, mbedtls_x509_crt_init, mbedtls_x509_crt_parse,
    };

    struct Contexts {
        crt: Box<mbedtls_x509_crt>,
        pk: Box<mbedtls_pk_context>,
    }

    impl Drop for Contexts {
        fn drop(&mut self) {
            // SAFETY: both contexts were initialized below and are freed once.
            unsafe {
                mbedtls_x509_crt_free(&mut *self.crt);
                mbedtls_pk_free(&mut *self.pk);
            }
        }
    }

    let cert_c = CString::new(cert_pem).map_err(|_| PairError::InvalidCertificate)?;
    let key_c = CString::new(key_pem).map_err(|_| PairError::InvalidPrivateKey)?;
    let mut ctx = Contexts { crt: Box::default(), pk: Box::default() };

    // SAFETY: fresh contexts and NUL-terminated PEM buffers valid for the
    // duration of each MbedTLS call.
    unsafe {
        mbedtls_x509_crt_init(&mut *ctx.crt);
        mbedtls_pk_init(&mut *ctx.pk);

        if mbedtls_x509_crt_parse(&mut *ctx.crt, cert_c.as_ptr().cast(), cert_c.count_bytes() + 1) != 0 {
            return Err(PairError::InvalidCertificate);
        }

        if mbedtls_pk_parse_key(
            &mut *ctx.pk,
            key_c.as_ptr().cast(),
            key_c.count_bytes() + 1,
            core::ptr::null(),
            0,
            Some(mbedtls_rng),
            core::ptr::null_mut(),
        ) != 0
        {
            return Err(PairError::InvalidPrivateKey);
        }

        if mbedtls_pk_check_pair(&ctx.crt.pk, &*ctx.pk, Some(mbedtls_rng), core::ptr::null_mut()) != 0 {
            return Err(PairError::Mismatch);
        }
    }

    Ok(())
}


#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
#[derive(Debug)]
pub enum IdentityGenerationError {
    InvalidName,
    PsaInit(i32),
    KeyGeneration(i32),
    KeySetup(i32),
    KeyEncoding(i32),
    CertificateSetup(i32),
    CertificateEncoding(i32),
    InvalidUtf8,
}

/// Fresh P-256 server identity generated locally.
///
/// The key is created as a volatile PSA key, wrapped by MbedTLS only for
/// certificate construction/export, then destroyed after its PEM form has
/// been produced. This crate deliberately does not persist it: persistence,
/// lifecycle and enrollment are application policy.
///
/// The self-signed certificate uses a deliberately wide fixed validity
/// window because bootstrap identity creation can happen before networking
/// and therefore before the application has synchronized a wall clock.
#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
pub struct GeneratedIdentity {
    pub cert_pem: alloc::string::String,
    pub key_pem: alloc::string::String,
}

#[cfg(any(feature = "esp32c3", feature = "esp32s3"))]
pub fn generate_self_signed_identity(
    common_name: &str,
) -> Result<GeneratedIdentity, IdentityGenerationError> {
    use mbedtls_rs::sys::{
        mbedtls_md_type_t_MBEDTLS_MD_SHA256, mbedtls_pk_context, mbedtls_pk_free,
        mbedtls_pk_init, mbedtls_pk_setup_opaque, mbedtls_pk_write_key_pem,
        mbedtls_x509write_cert, mbedtls_x509write_crt_free,
        mbedtls_x509write_crt_init, mbedtls_x509write_crt_pem,
        mbedtls_x509write_crt_set_basic_constraints,
        mbedtls_x509write_crt_set_issuer_key, mbedtls_x509write_crt_set_issuer_name,
        mbedtls_x509write_crt_set_md_alg, mbedtls_x509write_crt_set_serial_raw,
        mbedtls_x509write_crt_set_subject_key, mbedtls_x509write_crt_set_subject_name,
        mbedtls_x509write_crt_set_validity, psa_crypto_init, psa_destroy_key,
        psa_generate_key, psa_key_attributes_t,
    };

    // PSA encodings from the PSA Crypto specification. They are macros in C,
    // so bindgen does not expose constructors for them.
    const PSA_SUCCESS: i32 = 0;
    const PSA_ECC_FAMILY_SECP_R1: u16 = 0x12;
    const PSA_KEY_TYPE_ECC_KEY_PAIR_BASE: u16 = 0x7100;
    const PSA_KEY_USAGE_EXPORT: u32 = 0x0000_0001;
    const PSA_KEY_USAGE_SIGN_HASH: u32 = 0x0000_1000;
    const PSA_ALG_SHA_256: u32 = 0x0200_0009;
    const PSA_ALG_ECDSA_BASE: u32 = 0x0600_0600;
    const KEY_TYPE: u16 = PSA_KEY_TYPE_ECC_KEY_PAIR_BASE | PSA_ECC_FAMILY_SECP_R1;
    const SIGN_ALG: u32 = PSA_ALG_ECDSA_BASE | (PSA_ALG_SHA_256 & 0xff);

    struct Contexts {
        pk: Box<mbedtls_pk_context>,
        crt: Box<mbedtls_x509write_cert>,
        key_id: u32,
    }

    impl Drop for Contexts {
        fn drop(&mut self) {
            // SAFETY: contexts were initialized below; an all-zero key id is
            // never a valid PSA key and is ignored.
            unsafe {
                mbedtls_x509write_crt_free(&mut *self.crt);
                mbedtls_pk_free(&mut *self.pk);
                if self.key_id != 0 {
                    let _ = psa_destroy_key(self.key_id);
                }
            }
        }
    }

    let subject = alloc::format!("CN={common_name}");
    let subject = CString::new(subject).map_err(|_| IdentityGenerationError::InvalidName)?;
    let mut ctx = Contexts {
        pk: Box::default(),
        crt: Box::default(),
        key_id: 0,
    };

    // SAFETY: all calls receive initialized contexts and valid buffers.
    unsafe {
        let rc = psa_crypto_init();
        if rc != PSA_SUCCESS {
            return Err(IdentityGenerationError::PsaInit(rc));
        }

        let mut attributes = psa_key_attributes_t::default();
        attributes.private_type = KEY_TYPE;
        attributes.private_bits = 256;
        attributes.private_lifetime = 0; // PSA_KEY_LIFETIME_VOLATILE
        attributes.private_policy.private_usage =
            PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH;
        attributes.private_policy.private_alg = SIGN_ALG;
        attributes.private_policy.private_alg2 = 0;
        attributes.private_id = 0;

        let rc = psa_generate_key(&attributes, &mut ctx.key_id);
        if rc != PSA_SUCCESS || ctx.key_id == 0 {
            return Err(IdentityGenerationError::KeyGeneration(rc));
        }

        mbedtls_pk_init(&mut *ctx.pk);
        let rc = mbedtls_pk_setup_opaque(&mut *ctx.pk, ctx.key_id);
        if rc != 0 {
            return Err(IdentityGenerationError::KeySetup(rc));
        }

        mbedtls_x509write_crt_init(&mut *ctx.crt);
        let mut setup = |rc: i32| {
            if rc == 0 {
                Ok(())
            } else {
                Err(IdentityGenerationError::CertificateSetup(rc))
            }
        };
        setup(mbedtls_x509write_crt_set_subject_name(
            &mut *ctx.crt,
            subject.as_ptr(),
        ))?;
        setup(mbedtls_x509write_crt_set_issuer_name(
            &mut *ctx.crt,
            subject.as_ptr(),
        ))?;
        mbedtls_x509write_crt_set_subject_key(&mut *ctx.crt, &mut *ctx.pk);
        mbedtls_x509write_crt_set_issuer_key(&mut *ctx.crt, &mut *ctx.pk);

        let mut serial = [0u8; 16];
        Rng::new().read(&mut serial);
        serial[0] &= 0x7f;
        serial[0] |= 0x01;
        setup(mbedtls_x509write_crt_set_serial_raw(
            &mut *ctx.crt,
            serial.as_ptr(),
            serial.len(),
        ))?;

        setup(mbedtls_x509write_crt_set_validity(
            &mut *ctx.crt,
            c"20260101000000".as_ptr(),
            c"20991231235959".as_ptr(),
        ))?;
        mbedtls_x509write_crt_set_md_alg(
            &mut *ctx.crt,
            mbedtls_md_type_t_MBEDTLS_MD_SHA256,
        );
        setup(mbedtls_x509write_crt_set_basic_constraints(
            &mut *ctx.crt,
            0,
            -1,
        ))?;

        let mut key_buf = [0u8; 1024];
        let rc = mbedtls_pk_write_key_pem(
            &*ctx.pk,
            key_buf.as_mut_ptr(),
            key_buf.len(),
        );
        if rc != 0 {
            return Err(IdentityGenerationError::KeyEncoding(rc));
        }

        let mut cert_buf = [0u8; 2048];
        let rc = mbedtls_x509write_crt_pem(
            &mut *ctx.crt,
            cert_buf.as_mut_ptr(),
            cert_buf.len(),
            Some(mbedtls_rng),
            core::ptr::null_mut(),
        );
        if rc != 0 {
            return Err(IdentityGenerationError::CertificateEncoding(rc));
        }

        fn pem_string(
            buf: &[u8],
        ) -> Result<alloc::string::String, IdentityGenerationError> {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let text = core::str::from_utf8(&buf[..end])
                .map_err(|_| IdentityGenerationError::InvalidUtf8)?;
            Ok(alloc::string::String::from(text))
        }

        Ok(GeneratedIdentity {
            cert_pem: pem_string(&cert_buf)?,
            key_pem: pem_string(&key_buf)?,
        })
    }
}

/// Builds a server-side MbedTLS session configuration from a PEM pair.
pub fn server_config_from_pem(cert_pem: &str, key_pem: &str) -> Result<SessionConfig<'static>, ()> {
    let cert_c = CString::new(cert_pem).map_err(|_| ())?;
    let key_c = CString::new(key_pem).map_err(|_| ())?;
    let certificate = Certificate::new(X509::PEM(&cert_c)).map_err(|_| ())?;
    let private_key = PrivateKey::new(X509::PEM(&key_c), None).map_err(|_| ())?;
    Ok(SessionConfig::Server(ServerSessionConfig::new(Credentials { certificate, private_key })))
}

/// Verifies that a CA PEM parses as an X.509 certificate.
pub fn validate_ca_pem(ca_pem: &str) -> bool {
    let Ok(ca_c) = CString::new(ca_pem) else {
        return false;
    };
    Certificate::new(X509::PEM(&ca_c)).is_ok()
}

#[cfg(feature = "embassy-net")]
pub mod embassy {
    use alloc::ffi::CString;

    use embassy_net::tcp::{ConnectError, TcpSocket};
    use mbedtls_rs::{
        Certificate, ClientSessionConfig, Session, SessionConfig, SessionError, TlsReference, X509,
    };

    /// Failures in DNS/TCP/TLS establishment. Application policy such as
    /// "clock not synchronized" or "CA not provisioned" intentionally stays
    /// outside this crate.
    #[derive(Debug)]
    pub enum ClientConnectError {
        BadCa,
        Dns,
        Tcp(ConnectError),
        Handshake(SessionError),
    }

    /// Resolve, connect, and complete a certificate-verifying client TLS
    /// handshake over Embassy networking.
    pub async fn connect_client<'h, 'buf>(
        tls: TlsReference<'static>,
        stack: embassy_net::Stack<'static>,
        rx_buffer: &'buf mut [u8],
        tx_buffer: &'buf mut [u8],
        host: &'h core::ffi::CStr,
        port: u16,
        ca_pem: &str,
    ) -> Result<Session<'h, TcpSocket<'buf>>, ClientConnectError> {
        let ca_c = CString::new(ca_pem).map_err(|_| ClientConnectError::BadCa)?;
        let ca_chain = Certificate::new(X509::PEM(&ca_c)).map_err(|_| ClientConnectError::BadCa)?;

        let host_str = host.to_str().map_err(|_| ClientConnectError::Dns)?;
        let dns = embassy_net::dns::DnsSocket::new(stack);
        let ip = dns
            .query(host_str, embassy_net::dns::DnsQueryType::A)
            .await
            .ok()
            .and_then(|addrs| addrs.into_iter().next())
            .ok_or(ClientConnectError::Dns)?;

        let mut socket = TcpSocket::new(stack, rx_buffer, tx_buffer);
        socket.connect((ip, port)).await.map_err(ClientConnectError::Tcp)?;

        let config = SessionConfig::Client(ClientSessionConfig {
            ca_chain: Some(ca_chain),
            server_name: Some(host),
            ..ClientSessionConfig::new()
        });
        let mut session = Session::new(tls, socket, &config).map_err(ClientConnectError::Handshake)?;
        session.connect().await.map_err(ClientConnectError::Handshake)?;
        Ok(session)
    }

    #[cfg(feature = "picoserve")]
    mod picoserve_adapter {
        use embassy_net::tcp::TcpSocket;
        use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
        use embassy_sync::mutex::Mutex;
        use mbedtls_rs::io::{ErrorType, Read};
        use mbedtls_rs::{Session, SessionError};
        use picoserve::mem::BorrowedBuffer;

        /// A connected MbedTLS session adapted to picoserve's socket trait.
        pub struct TlsSocket<'tls, 'buf> {
            session: Mutex<CriticalSectionRawMutex, Session<'tls, TcpSocket<'buf>>>,
        }

        impl<'tls, 'buf> TlsSocket<'tls, 'buf> {
            pub fn new(session: Session<'tls, TcpSocket<'buf>>) -> Self {
                Self { session: Mutex::new(session) }
            }
        }

        pub struct TlsHalf<'tls, 'buf, 'b> {
            session: &'b Mutex<CriticalSectionRawMutex, Session<'tls, TcpSocket<'buf>>>,
        }

        impl ErrorType for TlsHalf<'_, '_, '_> {
            type Error = SessionError;
        }

        impl Read for TlsHalf<'_, '_, '_> {
            async fn read(&mut self, buf: &mut [u8]) -> Result<usize, SessionError> {
                self.session.lock().await.read(buf).await
            }
        }

        impl mbedtls_rs::io::Write for TlsHalf<'_, '_, '_> {
            async fn write(&mut self, buf: &[u8]) -> Result<usize, SessionError> {
                self.session.lock().await.write(buf).await
            }

            async fn flush(&mut self) -> Result<(), SessionError> {
                self.session.lock().await.flush().await
            }
        }

        impl picoserve::io::Write for TlsHalf<'_, '_, '_> {
            async fn write_with<F: FnOnce(picoserve::mem::BorrowedCursor<'_>) -> R, R>(
                &mut self,
                f: F,
            ) -> Result<R, SessionError> {
                let mut buffer = [0u8; 1024];
                let mut buffer = BorrowedBuffer::new(&mut buffer);
                let output = f(buffer.unfilled());
                self.session.lock().await.write(buffer.filled()).await?;
                Ok(output)
            }
        }

        impl<'tls, 'buf> picoserve::io::Socket<picoserve::EmbassyRuntime> for TlsSocket<'tls, 'buf> {
            type Error = SessionError;
            type ReadHalf<'b> = TlsHalf<'tls, 'buf, 'b> where Self: 'b;
            type WriteHalf<'b> = TlsHalf<'tls, 'buf, 'b> where Self: 'b;

            fn split(&mut self) -> (Self::ReadHalf<'_>, Self::WriteHalf<'_>) {
                (
                    TlsHalf { session: &self.session },
                    TlsHalf { session: &self.session },
                )
            }

            async fn abort<T: picoserve::time::Timer<picoserve::EmbassyRuntime>>(
                self,
                _timeouts: &picoserve::Timeouts,
                _timer: &T,
            ) -> Result<(), picoserve::Error<Self::Error>> {
                let mut session = self.session.into_inner();
                session.stream().abort();
                Ok(())
            }

            async fn shutdown<T: picoserve::time::Timer<picoserve::EmbassyRuntime>>(
                self,
                _timeouts: &picoserve::Timeouts,
                _timer: &T,
            ) -> Result<(), picoserve::Error<Self::Error>> {
                let mut session = self.session.into_inner();
                let _ = session.close().await;
                session.stream().close();
                Ok(())
            }
        }

        pub use TlsSocket as PicoserveTlsSocket;
    }

    #[cfg(feature = "picoserve")]
    pub use picoserve_adapter::PicoserveTlsSocket;
}

#[cfg(test)]
mod tests {
    use super::epoch_to_tm;

    #[test]
    fn epoch_conversion_known_dates() {
        let t = epoch_to_tm(0).unwrap();
        assert_eq!(t.tm_year, 70);
        assert_eq!(t.tm_mon, 0);
        assert_eq!(t.tm_mday, 1);
        assert_eq!(t.tm_wday, 4);

        let t = epoch_to_tm(1_709_164_800).unwrap(); // 2024-02-29 00:00:00 UTC
        assert_eq!(t.tm_year, 124);
        assert_eq!(t.tm_mon, 1);
        assert_eq!(t.tm_mday, 29);
        assert_eq!(t.tm_yday, 59);
    }
}
