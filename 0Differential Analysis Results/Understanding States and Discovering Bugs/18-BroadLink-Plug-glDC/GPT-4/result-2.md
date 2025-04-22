# State Semantic mapping table

| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state where no devices are controlled, and no invitations have been sent. User2 has no permissions. |
| s1    | User1 has added a device and can control it. User2 has no permissions. |
| s2    | User1 is able to control devices, but User2 has no control or permissions. |
| s3    | User1 has added a device and sent an invitation to User2. User2 has not accepted the invitation yet. |
| s4    | User1 can control the device and has invited User2. User2 has not yet accepted the invitation. |
| s5    | User1 can control the device, and User2 has accepted the invitation, now a family member with device control permissions. |
| s6    | User1 is controlling the device, and User2 has successfully joined the family, with the ability to control devices. |
| s7    | User1 has full control over devices, while User2 is also a family member with full device control. |
| s8    | User1 has control of devices, and User2 has control too, but might be in a state where actions can fail (e.g., scanning a QR code). |
| s9    | User1 has control over devices, and User2 has been invited but may not yet have control permissions. |
| s10   | User1 controls the devices, and User2 is a family member but might not have control yet. |
| s11   | User1 has control over devices, and User2's permissions could have been temporarily revoked or altered. |
| s12   | User1 has control, and User2 may be temporarily denied device control after an action. |
| s13   | User1 has device control, and User2 is a full member, meaning both users have equal permissions. |
| s14   | User1 controls the devices, and User2 has been invited again with full permissions to control devices. |
| s15   | User1 has full control over devices, and User2 is also granted control. However, actions by User2 may be restricted. |
| s16   | User1 can manage devices, but User2's actions may fail due to invalid permissions. |
| s17   | User1 has control over devices, while User2 might be in a temporary restricted state. |
| s18   | User1 maintains control over devices, and User2 has successful control rights but with occasional operation failures. |
| s19   | User1 is in control, and User2's permissions are still active but can occasionally fail based on the state. |
| s20   | User1 controls the devices, and User2 can still perform actions as a family member with some potential failures. |
| s21   | User1 has full control over devices, while User2 has control permissions but might encounter some errors. |
| s22   | User1 maintains control, but User2's actions may fail or require validation due to inconsistencies. |
| s23   | User1 has full control, and User2's permissions are still active, though some actions may fail based on errors. |
| s24   | User1 has full control, and User2 still maintains control rights, but some actions may be inconsistent. |
| s25   | User1 controls the devices, and User2 has permissions but might be blocked from executing certain actions. |
| s26   | User1 controls devices, and User2 is restricted from certain actions due to failed permissions or conditions. |
| s27   | User1 manages devices, and User2 is in a restricted state where permissions are temporarily unavailable. |
| s28   | User1 is in control, while User2 may have limited permissions due to failure scenarios in operations. |
| s29   | User1 is the primary device controller, and User2 has certain rights but can encounter errors with actions. |
| s30   | User1 manages devices, and User2 has full permissions but with potential failures in operations. |
| s31   | User1 is in control, and User2 has control but may encounter temporary restrictions in actions. |
| s32   | User1 manages devices, and User2 has been granted control but may experience operation failures. |

# Critical Vulnerability report

## Vulnerability 1: Unauthorized access through replay of device control
**Threat Level**: High Risk

**Attack Path**:
1. Attackers accumulate knowledge through successfully accepting the invitation (`user2|remote|AcceptInvite`) and control of devices.
2. Replay the `user2|local|DeviceControl` action in state s15 or s16 to gain unauthorized control of devices.
3. Bypass the check to enter the privileged state and control devices without full permissions.

**Repeat steps**:
Starting from state s0, perform the operation `user1|local|InviteToHome` to reach state s4, then perform operation `user2|remote|AcceptInvite` to reach state s5. The attacker can replay `user2|local|DeviceControl` in state s15 or s16 to attempt unauthorized control over the device.