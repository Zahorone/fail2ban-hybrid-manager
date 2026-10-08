# IPv6 design notes for v0.34

Fail2Ban performs address-family selection. The packaged
`nftables-multiport.conf` therefore remains an upstream-compatible shim that
includes `nftables.conf`; it must not hard-code an IPv4 `actionban`.

The project-specific family mapping is:

- IPv4: `f2b-<jail>`
- IPv6: `f2b-<jail>-v6`
- recidive IPv4: `f2b-recidive`
- recidive IPv6: `f2b-recidive-v6`

CI namespace tests prove local nftables behaviour, but they do not prove public
IPv6 reachability. Canary acceptance requires an external end-to-end IPv6 test
against a host whose provider routing is enabled.
