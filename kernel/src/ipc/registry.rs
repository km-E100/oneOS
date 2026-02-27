#![cfg(target_os = "none")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::sandbox::DomainId;

#[derive(Clone, Debug)]
pub struct ServiceInfo {
    pub name: String,
    pub domain_id: DomainId,
}

static REGISTRY: Mutex<Vec<ServiceInfo>> = Mutex::new(Vec::new());

pub fn register(name: &str, domain_id: DomainId) {
    let mut reg = REGISTRY.lock();
    if let Some(e) = reg.iter_mut().find(|e| e.name == name) {
        e.domain_id = domain_id;
        return;
    }
    reg.push(ServiceInfo {
        name: name.into(),
        domain_id,
    });
}

pub fn unregister_by_domain(domain_id: DomainId) {
    let mut reg = REGISTRY.lock();
    reg.retain(|e| e.domain_id != domain_id);
}

pub fn resolve(name: &str) -> Option<DomainId> {
    let reg = REGISTRY.lock();
    reg.iter().find(|e| e.name == name).map(|e| e.domain_id)
}

pub fn list() -> Vec<ServiceInfo> {
    REGISTRY.lock().clone()
}
