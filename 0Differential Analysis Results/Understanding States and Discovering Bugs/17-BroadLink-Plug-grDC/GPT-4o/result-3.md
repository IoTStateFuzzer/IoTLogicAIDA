# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| s0 | Initial state where no device is added, and no device control permissions exist. User1 can add or remove devices and invite users. User2 has no control over devices or permissions. |
| s1 | User1 has added a device, but no device control permission has been granted to User2. User1 can still invite users and control devices locally and remotely. User2 has no permissions. |
| s2 | Device added, but neither user has control over it. Operations by either user related to device control or inviting users are not executable at this state. |
| s3 | User1 has invited User2 to the home. User1 can still manage devices, and User2 can scan the invitation QR code. No device control yet for User2. |
| s4 | User1 has invited User2 to the home, and User2 has not yet accepted the invitation. User1 can manage devices, while User2 has no permissions or device control. |
| s5 | User2 has accepted the invitation and can control devices temporarily. User1 can manage devices and share control permissions. User2 has limited control rights. |
| s6 | User2 has accepted the invitation and gained temporary device control permissions. User1 can still manage devices, and User2 can perform some control operations remotely. |
| s7 | User1 can control the devices remotely, and User2 can attempt to control devices but has no valid permissions. |
| s8 | User1 manages devices and invites users. User2 can attempt to control devices but still lacks valid permissions to execute device control. |
| s9 | User1 can control devices, but User2 does not have the right to control devices. Both users are in a state where actions related to sharing devices or device control are not allowed. |
| s10 | User1 has invited User2 into the home, but no device control permissions are granted. Both users can perform different operations, with User2 attempting to interact through scanning or quitting but lacking permissions. |
| s11 | User1 has successfully invited User2 and continues to manage devices. User2 can attempt some actions but lacks permission for control or scanning. |
| s12 | User1 can manage devices and has invited User2. User2 attempts to perform actions but receives failure responses when trying to control devices or access certain features. |
| s13 | User1 has added devices and invited User2. User2 lacks control rights and can perform limited actions like scanning but cannot control devices. |
| s14 | User1 controls devices and invites users. User2, despite attempts, cannot interact with devices in a meaningful way due to lack of permissions. |
| s15 | User1 continues to control devices, and User2 can attempt actions but does not have valid permissions for full interaction with devices. |
| s16 | User1 is allowed to control devices, but User2’s actions related to devices, such as scanning, receive errors indicating insufficient permissions. |
| s17 | User1 has full control over devices, while User2’s actions like scanning or accepting invitations result in failure due to missing permissions. |
| s18 | User1 has complete device control. User2 may receive errors during operations due to lack of valid permissions or requirements like device resets. |
| s19 | User1 has full control, while User2 can perform limited actions but is restricted from making meaningful changes or controlling devices. |
| s20 | User1 manages devices, while User2’s actions may fail due to missing permissions, especially with operations like scanning or quitting the home. |
| s21 | User1 has full control, and User2’s actions are mostly restricted, with some attempts failing due to insufficient permissions. |
| s22 | User1 has full control, and User2 faces errors while interacting with devices or attempting actions like scanning and accepting invitations. |
| s23 | User1 continues controlling devices. User2’s actions receive failures or insufficient responses, indicating a lack of permissions. |
| s24 | User1 manages devices and invites users, but User2 faces failures in interacting with devices due to missing permissions. |
| s25 | User1 is managing devices, while User2 has limited actions and faces failures when trying to control devices remotely. |
| s26 | User1 has complete control over devices, while User2 cannot successfully perform any meaningful actions. |
| s27 | User1 can control devices, while User2 continues to be restricted in performing meaningful operations. |
| s28 | User1 manages devices, while User2 faces multiple failures in interacting with devices remotely. |
| s29 | User1 has full control over devices, and User2 experiences restrictions when attempting device control. |
| s30 | User1 manages devices, but User2’s actions are limited or result in failures due to lack of valid permissions. |
| s31 | User1 continues managing devices, while User2 faces multiple failures, such as not being able to control devices. |
| s32 | User1 has full control over devices, and User2’s actions are mostly restricted or result in failures due to insufficient permissions. |

---

### Vulnerability Report

**Everything is OK**: No critical vulnerabilities detected in the statefuzzing model. However, it is essential to continuously verify that user permissions and device control features are properly isolated and tested to prevent unauthorized access, especially considering scenarios where the attacker (User2) tries to replay actions or bypass permissions.