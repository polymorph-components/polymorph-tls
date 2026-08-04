//! `std::net::SocketAddr` ↔ `wasi:sockets` address conversions.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use wasi::sockets::network::{
    IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress,
};

pub(crate) fn to_wasi(addr: SocketAddr) -> IpSocketAddress {
    match addr {
        SocketAddr::V4(v4) => IpSocketAddress::Ipv4(Ipv4SocketAddress {
            port: v4.port(),
            address: {
                let [a, b, c, d] = v4.ip().octets();
                (a, b, c, d)
            },
        }),
        SocketAddr::V6(v6) => IpSocketAddress::Ipv6(Ipv6SocketAddress {
            port: v6.port(),
            flow_info: v6.flowinfo(),
            scope_id: v6.scope_id(),
            address: {
                let [a, b, c, d, e, f, g, h] = v6.ip().segments();
                (a, b, c, d, e, f, g, h)
            },
        }),
    }
}

pub(crate) fn from_wasi(addr: IpSocketAddress) -> SocketAddr {
    match addr {
        IpSocketAddress::Ipv4(v4) => {
            let (a, b, c, d) = v4.address;
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), v4.port))
        }
        IpSocketAddress::Ipv6(v6) => {
            let (a, b, c, d, e, f, g, h) = v6.address;
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(a, b, c, d, e, f, g, h),
                v6.port,
                v6.flow_info,
                v6.scope_id,
            ))
        }
    }
}

pub(crate) fn family(addr: SocketAddr) -> IpAddressFamily {
    match addr {
        SocketAddr::V4(_) => IpAddressFamily::Ipv4,
        SocketAddr::V6(_) => IpAddressFamily::Ipv6,
    }
}
