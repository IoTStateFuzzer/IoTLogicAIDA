# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state, all actions are unavailable for user2 (attacker), user1 can perform normal operations like adding or removing devices. |
| s1    | User1 can successfully control devices; user2 has no control permissions. User1 can invite others. |
| s2    | State where both users are restricted from interacting with devices; no actions can be executed. |
| s3    | User1 can continue device control; user2 is invited but has no access to device control yet. |
| s4    | User1 can manage devices; user2 can accept invites or scan QR codes. |
| s5    | User1 can control devices; user2 has now successfully accepted the invitation and can interact with devices. |
| s6    | Both users have device control; user1 can re-invite others, but user2 cannot re-scan QR codes due to a failure. |
| s7    | Normal operations for both users; user1 can control devices, and user2 can interact with devices normally. |
| s8    | User2 cannot scan the QR code, but other operations can continue for both users. |
| s9    | User2's operations are still limited. User1 maintains device control and can re-invite user2. |
| s10   | Same as s9; user2 has limited permissions, but no other issues. |
| s11   | User1 maintains normal control; user2 cannot perform meaningful actions yet. |
| s12   | Normal state where both users have control, but user2's actions are still restricted. |
| s13   | User1 can add and remove devices; user2 is unable to make meaningful changes but can accept invitations. |
| s14   | Same as s13; user1 can still control the device, but user2's actions are limited after a failed attempt to scan the QR code. |
| s15   | User2 has temporarily gained device control and can act like a normal user for the current session. |
| s16   | User2 has control capabilities, but a failure in scanning the QR code prevents full interaction. |
| s17   | Similar to s16; user1 can continue normal operations, and user2 still faces restrictions. |
| s18   | No significant changes for both users; user2 is still restricted in some areas. |
| s19   | User1 maintains full control; user2 can attempt to quit but does not gain device control. |
| s20   | User2 has limited permissions and actions in this state. |
| s21   | Both users are still functional, but user2 is restricted from scanning QR codes. |
| s22   | User2 cannot perform any actions until further changes. |
| s23   | Normal interaction for user1; user2’s actions are restricted. |
| s24   | Normal interaction with additional invitation options for both users, but user2 is still restricted in certain areas. |
| s25   | Both users can perform actions, but user2 is still restricted in some aspects like QR scanning. |
| s26   | User2 can still try to gain control but faces limitations in certain areas of the interaction. |
| s27   | Both users can interact, but user2 faces more restrictions. |
| s28   | User2 can now interact with the device after gaining control permissions in this state. |
| s29   | Both users are functional, but user2 still faces restrictions on certain operations. |
| s30   | No significant issues in this state; user2 is still restricted in certain actions. |
| s31   | User2 faces limitations in interacting with the device, but user1 can continue their operations. |
| s32   | User2 can interact with the device, but a failure prevents further progress in scanning QR codes. |

---

### Critical Vulnerability Report

#### Vulnerability 1: Information Leakage from Privilege Escalation

**Threat Level**: High Risk

**Attack Path**:
1. The attacker (user2) gains temporary control of the device.
2. The attacker uses their control to interact with the device.
3. The attacker attempts to re-access device control after permission revocation.
4. The attacker is still able to access some device information despite revocation.

**Repeat Steps**:
1. Starting from state s0, user1 invites user2 into the family.
2. User2 accepts the invitation and temporarily gains control in state s5.
3. After user1 revokes user2’s permission, user2 can attempt to re-access the device in later states (e.g., s19).
4. The attacker can still see device details or interact with the device, even after permission is revoked, representing a privacy violation.

This vulnerability allows the attacker to gain unauthorized access to device information after control is revoked.