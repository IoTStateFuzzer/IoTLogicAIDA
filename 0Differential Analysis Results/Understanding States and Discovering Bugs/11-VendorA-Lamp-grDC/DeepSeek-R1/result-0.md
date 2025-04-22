

# State Semantic mapping table

State | semantic description
-----|---------
0 | Initial state: No devices added, no users invited. User1 can add devices or invite user2.
1 | Device added by user1. User1 can remove device, invite user2, or control device.
2 | Error state - indicates invalid operations (e.g., controlling non-existent devices).
3 | user2 invited to home (family member status) without any devices. User1 can add devices or remove user2.
4 | Valid sharing state: user1 has device, user2 has full control permissions through UI. Attacker can click DeviceControl.
5 | Persistent control state: user2 retains DeviceControl capability through API replay (KS contains DeviceControl knowledge).
6 | Device removed after being in shared state. user2's API attempts fail but KS remains.
7 | user2 removed from home after device sharing. API controls return authorization errors but KS persists.
8 | Device removed after user removal. System in clean state but attacker KS remains.
9 | Device re-added after complex state transitions. user2's API controls fail but KS persists.
10 | Device re-added after removal cycle. user2 can reactivate control via KS to return to state 5.

# Critical Vulnerability report

## Vulnerability 1: Persistent Device Control Through State Resurrection
**Threat Level**: High Risk

**Attack Path**:
1. Attackers accumulate DeviceControl knowledge during legitimate sharing
2. Replay DeviceControl action after device removal-recovery cycle
3. Bypass permission revocation mechanism to regain control

**Repeat Steps**:
1. s0 → s1 (user1|local|AddDevice)
2. s1 → s4 (user1|local|InviteAndAccept)
3. s4 → s5 (user2|remote|DeviceControl)
4. s5 → s6 (user1|local|RemoveDevice)
5. s6 → s10 (user1|local|AddDevice)
6. s10 → s5 (user2|remote|DeviceControl)

**Impact**: Attacker maintains permanent device control capabilities through API replay, even after device removal and re-addition. The system fails to invalidate previous authorization contexts when devices are re-registered, violating authentication permanence principle (OWASP SC-003).