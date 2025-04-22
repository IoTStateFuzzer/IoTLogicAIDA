# State Semantic mapping table

| State | Semantic description |
|-------|----------------------|
| s0    | Initial state: The system is idle, no device is added or shared. User1 and user2 have no device control. |
| s1    | Device has been added by user1. User1 can control the device remotely. User2 has no permissions. |
| s2    | No device is shared or removed. Both users can attempt to control devices, but no successful actions are made. |
| s3    | Device sharing attempt by user1 failed. Device is removed. User2 can successfully accept device share. |
| s4    | Device is shared with user2. User1 can control the device remotely. User2 has the device control permissions. |
| s5    | Device has been removed, user2 can't accept the share invitation anymore. User1 can still control the device. |
| s6    | Device is shared again after removal. User2 is temporarily unable to accept the share invitation. |
| s7    | Device sharing succeeded. User2 can accept device share. |
| s8    | User2 has successfully accepted the share invitation but already in the family; can't accept the invitation again. |
| s9    | Device is shared but with issues related to the existing permission. User2 can still access the device. |
| s10   | Device is shared but user2 cannot accept the invitation due to the invalid invite. |
| s11   | Device is re-added after being removed. User2 can't control the device because the share was revoked. |
| s12   | Device is re-added, shared again. User2 can successfully control the device. |
| s13   | Device re-shared. User2 has successful access. |
| s14   | Device is shared and user2 can successfully control it. |
| s15   | Device sharing invitation has expired. User2 can't control the device. |
| s16   | User1 shares the device after removal. User2 can control the device again. |
| s17   | User1 can remotely control the device. User2 can access the device, despite unsuccessful share attempts. |
| s18   | User1 can control the device. User2 has expired invitation and can't accept share. |
| s19   | User2 can control the device, after being successfully re-shared. |
| s20   | User2 has access to control device after successful re-share. |
| s21   | User2 can control the device. Sharing issues persist but user2 is successfully controlling the device. |
| s22   | Device is shared with user2. User2 has control over the device. |

**Critical Vulnerability report**

## Vulnerability 1: Unauthorized Device Control for User2 after Revoking Permission
**Threat Level**: High Risk

**Attack Path**:
1. User1 invites user2 to the home, and user2 accepts the invitation, granting temporary device control permissions.
2. After revoking the control, user2 still attempts to control the device without proper validation.
3. User2 can bypass permission restrictions by reusing previous knowledge about device parameters and control, thus regaining unauthorized access.

**Repeat steps**:
Starting from state s0, perform the operation of user1 inviting user2, then user2 accepts. Revoke permission in state s4 and then attempt user2's control in s5 or later states.