# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state, no devices or user invitations. |
| s1    | Device added by user1, user1 has full control over the device. User2 has no permissions yet. |
| s2    | User1 can control devices, but user2 has no permissions or control rights. No active invitations. |
| s3    | Device is added by user1. User1 invites user2 into the home. User2 hasn't accepted the invitation yet. |
| s4    | Device added, user1 invited user2, and user2 hasn't accepted the invitation yet. |
| s5    | User1 invites user2. User2 accepts the invitation and joins the home. User2 has control of the devices as granted by user1. |
| s6    | User1 invited user2, and user2 accepted the invitation. User1 can still control the devices, user2 can control devices. |
| s7    | User1 invited user2, user2 has control rights after accepting the invitation. |
| s8    | User2 accepted the invitation and has control rights over the device. |
| s9    | User1 invited user2 but user2 is not yet assigned control permissions, unable to control devices. |
| s10   | User1 invited user2, and user2 accepted the invitation but has no control rights yet. |
| s11   | User2 accepted the invitation, but after some actions, the state shows user2 with no control over devices. |
| s12   | User2 accepted the invitation and has control rights, user1 can still control the devices. |
| s13   | Invitation from user1 to user2, device control operations available to both users. |
| s14   | User1 has invited user2, user2 accepted, and now both users can control devices together. |
| s15   | User1 and user2 can perform actions. User2's knowledge set enables device control actions. |
| s16   | User2 has a knowledge set allowing actions, but not control permissions yet. |
| s17   | User2 has a knowledge set allowing actions, device control disabled for user2. |
| s18   | User2 can interact with devices, but device reset is required before control can be gained. |
| s19   | User2’s interaction with devices is blocked, and user1 has full control. |
| s20   | User2's device control is temporarily disabled. Both users can control devices as normal. |
| s21   | User2 is restricted from device control despite having permissions to interact with devices. |
| s22   | User1 can still add/remove devices, while user2 is denied access to control devices. |
| s23   | User2 cannot interact with devices; reset required for user2 to regain permissions. |
| s24   | User2 is unable to control devices; they must leave the home to relinquish permissions. |
| s25   | User2 has a knowledge set, and user1 has control. Both users have their own permissions. |
| s26   | Device operations for user2 fail; user2 has a specific error while performing control actions. |
| s27   | User2 is granted permissions to interact with devices after user1's actions. |
| s28   | User2’s device control permissions are limited, and reset is required for functionality. |
| s29   | User2 interacts with devices, but has no permissions or control until specific operations are performed. |
| s30   | User2 performs operations but cannot control devices due to permission restrictions. |
| s31   | User2 can still perform operations but lacks control. Device control requires specific actions. |
| s32   | User2 is restricted from device control, requiring specific resets or actions to regain access. |

---

# Critical Vulnerability Report

## Vulnerability 1: Inconsistent Control Permissions for User2
**Threat Level**: High Risk

**Attack Path**:
1. The attacker (user2) gains temporary device control permissions by accepting an invitation from user1.
2. In state s6, user2 successfully accepts the invitation but is supposed to have control over the device.
3. In state s15, an attacker replays "user2|remote|DeviceControl" while not having permission, and control is granted unintentionally due to the failure to validate permissions properly.

**Repeat steps**:
Starting from state s0, perform operation "user1|local|InviteToHome" to reach state s3, then "user2|remote|AcceptInvite" to reach state s5. Finally, replay "user2|remote|DeviceControl" from state s5 to trigger unauthorized device control.