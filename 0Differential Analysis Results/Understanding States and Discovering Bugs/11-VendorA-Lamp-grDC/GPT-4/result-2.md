# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| s0 | The initial state where no devices are added, and no users have been invited or granted permissions. |
| s1 | User1 has attempted to add or remove devices, but these actions are unsuccessful. User2 does not have any device control permissions yet. |
| s2 | User1 has successfully added a device. User2 still has no control over the device, either locally or remotely. |
| s3 | User1 has invited and accepted the invitation to user2, but user2 is not yet granted control permissions. User2 can attempt to control the device, but operations will fail. |
| s4 | User1 has removed a device from the system successfully. The device is no longer available for control, and User2 is not granted any permissions for it. |
| s5 | User1 has successfully invited and accepted user2. In this state, User2 has gained remote device control permissions, and all operations will succeed for User2 as well. |
| s6 | User2 has remote control permissions for the device but cannot control it after being revoked. User1 may still manage the device without restrictions. |
| s7 | User1 successfully controls the device. User2's control capabilities have been revoked and all operations will fail. |
| s8 | User2's remote control attempt fails due to a lack of permissions. User1 continues to control the device successfully. |
| s9 | The system has successfully added a device, and User2 has been granted remote device control capabilities. User1 can still control the device, and User2 can also make successful control attempts. |
| s10 | User1 retains full control of the device. User2 continues to hold remote control permissions but is unable to perform any operations because of permission revocation. |

# Critical Vulnerability Report

## Vulnerability 1: Unauthorized Control via Knowledge Set (KS) Exploitation
**Threat Level**: High Risk

**Attack Path**:
1. Attacker (user2) accumulates knowledge through successful operations (e.g., accepting a device share, controlling a device remotely).
2. In state s5, user2 gains remote control permission, allowing them to control devices without restrictions. 
3. User2 can bypass permission revocations by retaining knowledge in their knowledge set, exploiting it to regain control.

**Repeat Steps**:
1. Starting from state s0, user1 adds a device successfully.
2. User1 then invites user2 into the system (state s3).
3. User2 accepts the invitation, and in state s5, user2 gains device control permissions.
4. User2's knowledge set retains information even after user1 revokes access, allowing user2 to replay remote control actions and regain control, posing a security risk.

## Vulnerability 2: Information Leakage via Invalid Control Attempts
**Threat Level**: Medium Risk

**Attack Path**:
1. Attacker (user2) performs an invalid control attempt on a device, even after permissions have been revoked.
2. The system may still respond with information about the device's status, potentially leaking details about user1’s device configuration.
3. This behavior can expose private information about devices that user2 should not access.

**Repeat Steps**:
1. Starting from state s4, user1 successfully removes the device from the system.
2. User2 attempts remote control and receives a failure response.
3. Even though the control fails, the failure response may leak information about the device, such as its operational status or failure codes, which should not be exposed to an unauthorized user.

# Summary:
- The main vulnerability arises from the attacker's ability to replay actions based on the knowledge stored in their knowledge set (KS) after receiving temporary control permissions.
- Although some inconsistencies in state transitions exist, they do not lead to critical security issues unless the attacker successfully exploits their knowledge set, bypassing permission revocation.
