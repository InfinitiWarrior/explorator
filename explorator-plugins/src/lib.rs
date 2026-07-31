pub mod certsh;
pub mod dns_wire;
pub mod dnsx;
pub mod httpx;
pub mod katana;
pub mod nuclei;
pub mod portscan;
pub mod subfinder;
pub mod whois;
pub mod x509;

use explorator_core::PluginRegistry;

/// Register every plugin implemented in this crate into `registry`.
pub fn register_all(registry: &mut PluginRegistry) {
    registry.register(Box::new(subfinder::SubfinderPlugin));
    registry.register(Box::new(dnsx::DnsxPlugin));
    registry.register(Box::new(whois::WhoisPlugin));
    registry.register(Box::new(certsh::CertshPlugin));
    registry.register(Box::new(httpx::HttpxPlugin));
    registry.register(Box::new(portscan::PortscanPlugin));
    registry.register(Box::new(katana::KatanaPlugin));
    registry.register(Box::new(nuclei::NucleiPlugin));
}
