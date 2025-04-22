# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state, no devices added, no user permissions set. |
| s1    | User1 has added a device, can perform device control operations. User2 has no permissions. |
| s2    | No permissions for either user, state after initial invitation or device control failure. |
| s3    | User1 can manage devices and invites, while User2 is still without permissions or has not yet accepted the invitation. |
| s4    | User1 has added devices, but User2 still has no permissions to control the devices. |
| s5    | User1 can invite User2 to the home. User2 has accepted the invitation and can now control devices. |
| s6    | User1's permissions to add or control devices continue. User2 has limited permissions based on the shared device state. |
| s7    | User1 maintains device control and can invite User2 again. User2 can control the devices remotely with permissions. |
| s8    | User1 maintains device control but User2 is unable to perform certain actions due to errors or permissions. |
| s9    | User1's actions allow invitations or device control, but User2 lacks permissions or encounters failures. |
| s10   | User1 and User2 can repeat the invitation process, with User2 controlling the device remotely. |
| s11   | User1 retains full control over devices. User2 has accepted the invitation and can control devices remotely. |
| s12   | User1 has successfully invited User2. User2's device control actions are still limited or fail occasionally. |
| s13   | User1 can control devices and invite User2 again. User2 successfully accepted the invite and has control permissions. |
| s14   | User1 maintains device control, and User2's permissions are intact for controlling devices remotely. |
| s15   | User1 manages devices and shares permissions. User2 is able to control devices remotely, though failures may occur occasionally. |
| s16   | User1 can still add or remove devices, and User2's control over devices may fail depending on conditions. |
| s17   | User1 continues with device control and invites. User2 faces device control failures or limited functionality. |
| s18   | User1 is active in device management and invitation, while User2 faces control restrictions or failures. |
| s19   | User1's device management actions continue successfully. User2 can control the devices remotely with possible failures. |
| s20   | User1 retains full control, while User2's attempts at device control are restricted. |
| s21   | User1 manages devices with full permissions. User2 has permissions to control devices remotely, but limitations persist. |
| s22   | User1 successfully manages devices, and User2 attempts to control devices, but faces failure occasionally. |
| s23   | User1 can manage devices and invitations. User2 faces difficulties or failures in device control. |
| s24   | User1 continues to manage devices, while User2's control is inconsistent or restricted. |
| s25   | User1 maintains device control, and User2's control is only successful intermittently. |
| s26   | User1 can add or remove devices. User2's ability to control devices may be impaired by failures or permission limitations. |
| s27   | User1 controls devices with full permissions. User2 faces intermittent failures when attempting to control devices. |
| s28   | User1 retains device management control. User2 experiences intermittent failures when controlling devices remotely. |
| s29   | User1 can manage devices successfully. User2 may succeed intermittently in controlling devices with remote access. |
| s30   | User1 and User2 can control devices, though some errors or failure conditions may occur with device control. |
| s31   | User1 is fully in control of devices, while User2 attempts to control devices but faces failure or lack of permissions. |
| s32   | User1 controls devices effectively. User2 may attempt actions that fail or succeed intermittently based on permissions. |

---

# Vulnerability Report

## Critical Vulnerability 1: Unauthorized Device Control After Re-invitation
**Threat Level**: High Risk

**Attack Path**:
1. The attacker (User2) accepts an invitation via QR code, granting temporary device control permissions.
2. User1 revokes the control permissions for User2 and re-invites User2.
3. The attacker (User2) attempts to replay previous device control actions via the UI or API, gaining unauthorized control of devices despite previous revocation.

**Repeat Steps**:
Starting from state s0, perform the operation of inviting User2 into the home, followed by revoking the invitation. After the re-invitation, User2 should not have device control permissions, but due to the lack of proper verification or state revalidation in s5, User2 can attempt to control the device using previously gained knowledge, potentially leading to unauthorized control. This exposes a vulnerability where state transitions fail to adequately prevent unauthorized access by attackers after control permissions are revoked and then re-granted.

