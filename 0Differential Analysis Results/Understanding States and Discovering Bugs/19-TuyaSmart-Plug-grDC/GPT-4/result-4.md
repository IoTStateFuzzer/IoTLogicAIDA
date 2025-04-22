# State Semantic Mapping Table

| State | Semantic Description |
|-------|----------------------|
| s0    | Initial state, no device is bound or shared. |
| s1    | User1 has bound the device. No sharing with user2. |
| s2    | Error state or no operation can be performed. |
| s3    | User1 has bound the device and shared it with user2. Both have control permissions. |
| s4    | User1 has bound the device and shared it with user2. Both have control permissions. User2 has knowledge for remote control and can click UI. |
| s5    | User1 has bound the device and revoked user2's permission, but user2 has knowledge for remote control. |
| s6    | User1 has unbound the device, user2 has knowledge for remote control but no device to control. |

# Base Model Report

Everything is OK.

# Divergent Model Report

## Vulnerability 1: Information Leakage and Unauthorized Control
**Impact effect**: User2 retains knowledge of remote device control even after permissions are revoked, potentially leading to unauthorized control attempts and information leakage about device status.

**Attack Path**:
1. User2 accumulates knowledge through successful remote control in state s3.
2. User1 revokes user2's permission, transitioning to state s5, but user2 retains knowledge.
3. User2 attempts to use the retained knowledge to control the device remotely in state s5, receiving a failed operation result, but this still indicates an attempt was made, which shouldn't happen as user2 should not have any information or control capability after permission revocation.