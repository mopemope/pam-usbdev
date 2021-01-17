#[macro_use]
extern crate log;
#[macro_use]
extern crate pam;
#[macro_use]
extern crate anyhow;

use anyhow::Result;
use log::LevelFilter;
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;
use syslog::{BasicLogger, Facility, Formatter3164};
use toml::from_str;

const CONFIG_FILE: &str = ".authorized_device";

#[derive(Debug, Deserialize, Clone)]
pub struct DeviceConfig {
    pub vendor_id: u16,
    pub product_id: u16,
}

struct PamOAuth;
pam_hooks!(PamOAuth);

pub fn parse_config(user: &str) -> io::Result<HashMap<String, DeviceConfig>> {
    let path = Path::new("/home").join(user).join(CONFIG_FILE);
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let mut config_toml = String::new();
    let mut f = File::open(path)?;
    f.read_to_string(&mut config_toml)?;
    let cfgs: HashMap<String, DeviceConfig> = from_str(&config_toml).expect("toml parse error");

    Ok(cfgs)
}

impl PamHooks for PamOAuth {
    fn sm_authenticate(pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // env::set_var("RUST_LOG", "debug");
        // env_logger::init();

        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "pam-razer".into(),
            pid: 0,
        };

        let logger = syslog::unix(formatter).expect("could not connect to syslog");

        let _ = log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
            .map(|()| log::set_max_level(LevelFilter::Info));

        let user = match pamh.get_user(None) {
            Ok(u) => u,
            Err(e) => return e,
        };

        let config = match parse_config(&user) {
            Ok(c) => c,
            Err(e) => {
                error!("{}", e);
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        match search_devices(config) {
            Ok(()) => PamResultCode::PAM_SUCCESS,
            _ => PamResultCode::PAM_AUTH_ERR,
        }
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn search_devices(config: HashMap<String, DeviceConfig>) -> Result<()> {
    let timeout = Duration::from_secs(1);

    let context = libusb::Context::new()?;

    for device in context.devices()?.iter() {
        let device_desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => continue,
        };

        let mut _usb_handle = {
            match device.open() {
                Ok(h) => match h.read_languages(timeout) {
                    Ok(l) => {
                        if !l.is_empty() {
                            Some(h)
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                },
                Err(_) => None,
            }
        };
        for c in config.values() {
            if device_desc.vendor_id() == c.vendor_id && device_desc.product_id() == c.product_id {
                return Ok(());
            }
        }
    }

    Err(anyhow!("not found"))
}
