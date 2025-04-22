# State Semantic Mapping Table

State | Semantic Description
-----|---------
s0 | Indicates the initial state where user1 has no actions performed, and user2 has no permissions.
s1 | user1 has successfully added a device.
s2 | Unavailable operations or failed operations for both user1 and user2.
s3 | user1 has shared the plug device, and user2 can accept the device share.
s4 | user1 has shared the device, and user2 has accepted the device share and can control the device.
s5 | user1 has shared the device, user2 has accepted the share, and user2 has controlled the device successfully.
s6 | user1 has unshared the device successfully after user2 controlled the device.
s7 | user1 has shared the device again, but user2 may control or accept the device share as well.
s8 | user1 has removed the device, returning to an initial state regarding the device presence.

# Critical Vulnerability Report

## Vulnerability 1: Unauthorized Device Control by user2
**Threat Level**: High Risk

**Attack Path**:
1. user1 shares the plug device while user2 collects knowledge.
2. user2 accepts the device share in state s3 and gains control over it (transition to s4).
3. In state s4, user2 controls the device, yet even after user1 tries to unshare the device (s5 to s6), user2 still controls it in s5.

**Repeat Steps**:
1. Starting from state s0, perform `user1|local|AddDevice` to reach state s1.
2. Perform `user1|local|SharePlug` in s1 to reach state s3.
3. On state s3, user2 performs `user2|remote|AcceptDeviceShare` to reach state s4.
4. Further perform `user2|remote|DeviceControl` in s4 to reach state s5.
5. `user1|local|UnsharePlug` in s5 to reach state s6; although designed to stop sharing, user2 can still operate in s5 (loop).

These steps indicate user2 retaining control and knowledge over the device after operations meant to revoke access by user1, implying a critical security threat.