# State Semantic mapping table

| State | Semantic description |
|-------|----------------------|
| s0    | Initial state, no device is added, no permissions assigned to user2, user2 cannot perform any actions. |
| s1    | User1 can add or remove devices, but no device exists at this point. No permissions are granted to user2. |
| s2    | A device is added by user1. User2 cannot control the device. User1 can manage the device (control actions are successful locally and remotely). |
| s3    | Device is added, user1 invites user2, and user2 accepts the invitation. Device control is successful for both user1 and user2. |
| s4    | A device is added, but user1 attempts to remove it. The operation succeeds, and the device is no longer available. User2 loses control over the device. |
| s5    | User2 can control the device remotely, even after being previously invited. Device control commands are successful for user2. |
| s6    | Device control is failed for user2 due to access errors. User1 can still add or remove devices, but no device control is allowed. |
| s7    | User1 removes the device, but user2's control is restricted. User1 can still control the device successfully. |
| s8    | User2 can control the device locally, but the operation results in an error when trying remotely. User1 can still manage the device. |
| s9    | User2 tries to control the device but encounters failure remotely. User1 manages the device successfully. |
| s10   | User2 successfully controls the device after gaining remote access, despite initial failures in earlier states. |

---

### Vulnerability Report

There are no significant vulnerabilities identified in the statefuzzing state machine. The attacker's actions are appropriately constrained, and there is no critical exposure of sensitive data or permissions beyond what is expected from the normal operations outlined in the state transitions.