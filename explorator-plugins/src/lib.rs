pub mod certsh;
pub mod dns_wire;
pub mod dnsx;
pub mod subfinder;
pub mod whois;

use explorator_core::PluginRegistry;

/// Register every plugin implemented in this crate into `registry`.
pub fn register_all(registry: &mut PluginRegistry) {
    registry.register(Box::new(subfinder::SubfinderPlugin));
    registry.register(Box::new(dnsx::DnsxPlugin));
    registry.register(Box::new(whois::WhoisPlugin));
    registry.register(Box::new(certsh::CertshPlugin));
}
