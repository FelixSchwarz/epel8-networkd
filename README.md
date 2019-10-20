# systemd-networkd for EPEL8

Red Hat decided not to ship systemd-networkd in RHEL 8 and recommends NetworkManager instead
([bug 1650342](https://bugzilla.redhat.com/show_bug.cgi?id=1650342)). I like networkd better on
my servers so this repo adds a new package "**systemd-networkd**" which can be installed on
CentOS 8/RHEL 8 *without replacing Red Hat's systemd*.

This work is based on Red Hat's systemd spec file and I tried to keep the changes as small
as possible.

**Alpha status**: I briefly tested the package in a VM and it seemed as if everything works but run your own tests before using this in production.

Limitations:

- I can not provide any security support. If there is a security bug in networkd Red Hat will
  likely not publish updates as they are not affected. If patching is easy I'm willing to
  carry an extra patch but I can't promise anything.
- Delays/breakage whenever Red Hat updates systemd: Right now systemd-networkd requires a very
  specific version of systemd. Probably I could relax the requirements but I wanted to err on the
  side of caution. It might take a while until I can update this package ("a while" as in "weeks",
  not just "days").

Please send a pull request if you spot errors/want to help with security fixes.

