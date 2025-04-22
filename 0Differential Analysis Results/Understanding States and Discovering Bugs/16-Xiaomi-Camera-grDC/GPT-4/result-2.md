# State Semantic mapping table

| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state. User1 can add a device, share/unshare camera, and remove a device. User2 cannot perform any actions initially. |
| s1    | User1 has successfully added a device and can now share the camera. User2 still cannot perform any actions. |
| s2    | Device is added, and user1 has device control. User2 has no control rights at this stage. |
| s3    | User1 can still control the device. User2 can now accept the device share. Sharing of the camera is unsuccessful due to limitations. |
| s4    | User2 has accepted the device share, granting them temporary control over the device. User1 can still perform actions like remove and unshare. |
| s5    | Device is successfully removed. User1 can add a new device or share the camera again. User2 can no longer control the device since the share invitation is expired. |
| s6    | Device has been removed by user1. User2 cannot accept the share invitation as it expired. |
| s7    | User1 is in a state where they can add a new device, but user2 has no control over the device anymore. |
| s8    | User2 can attempt to accept the share but fails as they are already part of the family. |
| s9    | User1 successfully controls the device; User2 may attempt to interact with the device, but they fail because of a failed invitation. |
| s10   | User1 can add a new device. User2 cannot interact with the device as their invitation is invalid. |
| s11   | User1 has shared the camera successfully. User2 cannot perform actions on the device due to an expired invitation. |
| s12   | User1 can manage devices and camera sharing. User2 attempts to interact but fails due to an expired invite. |
| s13   | User1 successfully controls the device. User2 has access to device control if they were successfully invited. |
| s14   | User1 can perform all actions, including sharing and removing the device. User2 can accept shared devices and control them temporarily. |
| s15   | Similar to previous states, User1 can control the device, while User2 may attempt to interact but will fail with expired permissions. |
| s16   | User1 controls the device remotely. User2 may attempt actions, but they are blocked due to invitation issues. |
| s17   | User1 can perform device-related actions. User2 can only perform temporary device control if they have accepted the share. |
| s18   | User1 has full control over the device. User2 cannot access it due to the expired share invite. |
| s19   | User1 successfully controls the device. User2 attempts to interact but fails with expired invitations. |
| s20   | Similar to previous states, User1 can manage the device while User2 can perform temporary actions if invited. |
| s21   | User1 can add a new device or manage current devices. User2 has control only if they accepted the device share invitation. |
| s22   | User1 successfully controls the device. User2 can interact if invited but their permissions are limited based on the invitation status. |

---

**Problem description**: Inconsistent state transitions between basemodel and statefuzzing.

**Problem Path**:
1. s5: user2|remote|DeviceControl is not properly handled in basemodel. In basemodel, it should result in "NoElement" if user2 is not invited.
2. s4: user1|local|UnshareCamera transitions to state s1, but in statefuzzing, it returns to s0 due to different permissions being set for user2.

# Critical Vulnerability report
## Vulnerability 1: Unauthorized device control via replay
**Threat Level**: High Risk

**Attack Path**:
1. Attackers accumulate knowledge by observing device control operations.
2. Replay the action "user2|remote|AcceptDeviceShare" in state s8.
3. Bypass the "invite check" and gain unauthorized device control.

**Repeat steps**:
Starting from state s0, perform operations to add a device and share the camera. Then, use the replayed attack at s8 to attempt unauthorized device control.