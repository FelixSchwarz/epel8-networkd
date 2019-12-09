# systemd-networkd for EPEL8

Red Hat decided not to ship systemd-networkd in RHEL 8 and recommends NetworkManager instead
([bug 1650342](https://bugzilla.redhat.com/show_bug.cgi?id=1650342)). I like networkd better on
my servers so this repo adds a new package "**systemd-networkd**" which can be installed on
CentOS 8/RHEL 8 *without replacing Red Hat's systemd*.

This work is based on Red Hat's systemd spec file and I tried to keep the changes as small
as possible.

**Beta status**: I'm using this package for several VMs which have pretty simple networking configurations. Please run your own tests before using this in production.

#### COPR for EPEL 8
The package is built in COPR: https://copr.fedorainfracloud.org/coprs/fschwarz/systemd-networkd/

#### Limitations

- I can not provide any security support. If there is a security bug in networkd Red Hat will
  likely not publish updates as they are not affected. If patching is easy I'm willing to
  carry an extra patch but I can't promise anything.
- Delays/breakage whenever Red Hat updates systemd: Right now systemd-networkd requires a very
  specific version of systemd. Probably I could relax the requirements but I wanted to err on the
  side of caution. It might take a while until I can update this package ("a while" as in "weeks",
  not just "days").
- The COPR repo is tracking CentOS 8 not RHEL 8. If CentOS lags a bit the packages will be out-of-date. I may provide a "preview" version in a separate branch but COPR will track the "master" branch.

Please send a pull request if you spot errors/want to help with security fixes.
