# CentOS 7 RPM header fixtures

`centos7-bash-header.bin` is the installed `bash-4.2.46-34.el7.x86_64`
header from the `/var/lib/rpm/Packages` database in
`quay.io/centos/centos@sha256:e4ca2ed0202e76be184e75fb26d14bf974193579039d5573fb2348664deef76e`.
Its SHA-256 is `0decb4f28b574bcc0caeb04a1c0b440c1f7cd51d041f3a677fda0bef5d7470a3`.
The full image is not checked in.

The committed `centos7-base-header-allowlist.json` admits only the exact
immutable header of `bash-4.2.46-34.el7.x86_64`. It was regenerated with
`go run ./scripts/centos7manifest -cache .git/taurus/centos7-rpms -output
.git/taurus/centos7-bash-manifest.json -packages bash`, then copied into this
directory for review. The generator verifies the official Vault 7.9.2009
`os/x86_64` repomd detached signature with the pinned CentOS key, the primary
metadata SHA-256, and the complete selected RPM against its metadata checksum.
The signed repomd SHA-256 is
`8b45b07b03813d3248c4fe4f407c4d9e4ebe91ca63591cc9e13243ec719c69e8`;
the full Bash RPM SHA-256 is
`f3a182414840db46fb19b893c33191dda43951f517234ff9393aa610daf3259e`.
Its reconstructed immutable header SHA-256 is
`91b32a50e95a388d3b1aa00dd5b6708c6107871397440ad10f1760c0221beafc`,
identical to the installed header fixture. Other CentOS-signed RPMs are
unsupported until their repository membership and full RPM bytes are verified
and their immutable header digests are added to the reviewed allowlist.

`centos7-extras-header.bin` is the installed header produced from the official
CentOS Vault 7.9.2009 Extras RPM
`WALinuxAgent-2.2.32-1.el7.noarch.rpm`. The full RPM's SHA-256 is
`30a0a7350c8ab79995b7f1005f09a8da39dade707033add95f5f6cad21270585`,
matching the Extras primary metadata. The installed header SHA-256 is
`55d222d811f872267ddf7ae064d9eb2689bacf5ffbb1f96ff4c261e9219a9655`.
It has a valid signature from the same CentOS 7 key, but is excluded from the
base allowlist and remains unsupported in the catalog regression test.

`centos-7-signing-key.asc` is the public CentOS 7 stable key from
[the CentOS key list](https://www.centos.org/keys/). Its SHA-256 is
`27b8180618f3d98428fff2cbefee2cffdeac05cdca14ab062d3c3ecdca1f2cd0`;
the test checks the full OpenPGP fingerprint
`6341AB2753D78A78A7C27BB124C6A8A7F4A80EB5` and the RSA modulus
against the scanner pin.

`epel7-release-header.bin` is the installed header from the public
`epel-release-7-14.noarch.rpm` package (RPM SHA-256
`e2d5ffdd4cfe09dde17018a31d100db611abe88cc6761d9bdc0c1f41eaa5aa0`).
Its own SHA-256 is `cad8d5c21d465261c7515d4fe74759562b2a268e188c487fdf98de0442426f4f`.
The negative test verifies that the CentOS 7 key does not authenticate it.
