## State Semantic mapping table

State | semantic description
-----|---------
s0 | Initial state: No device added, no sharing actions possible.
s1 | State after user1 adds a device: user1 can control the device and can share/unshare/remove the device.
s2 | Dead state: No actions can be performed.
s3 | State after user1 shares the device: user1 can control/unshare/remove the device, user2 can accept the device share.
s4 | State after user2 accepts the device share: user1 can control/unshare/remove the device, user2 can control the device.
s5 | Intermediate state: user1 can control/unshare/remove the device, user2 can control the device.
s6 | Intermediate state: user1 can control/unshare/share/remove the device, user2 can control the device.
s7 | Intermediate state: user1 can control/unshare/share/remove the device, user2 can accept the device share and control the device.
s8 | Dead state for user2, user1 can re-add the device, previous shares are invalid, user2 has no control.

## Critical Vulnerability report

### Vulnerability 1: Unauthorized Persistent Control by user2
** Threat Level ** : High Risk

** Attack Path **:
1. user1 adds a device and shares it with user2, reaching state s3.
2. user2 accepts the device share, and then performs a device control gaining control.
3. user1 unshares the device, moving to an intermediate state.
4. user2 continues performing device control despite the unshare, persisting control from state s5 onwards.

** Repeat steps **:
1. From state s0, user1|local|AddDevice to s1.
2. user1|local|SharePlug to s3.
3. user2|remote|AcceptDeviceShare to s4.
4. user1|local|UnsharePlug to s5.
5. user2|remote|DeviceControl (repeated control observed in state s5 and onwards).

This shows persistence of user2's control after user1 has unshared the device, indicating a flaw in state transition validation.