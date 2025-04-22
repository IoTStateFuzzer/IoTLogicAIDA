# State Semantic mapping table

State | Semantic Description
-----|---------
0 | Initial state where no devices have been added, and user2 has no permissions.
1 | User1 has added a device, but has not shared it with user2.
2 | No valid operations possible (failure state for any attempt).
3 | User1 has added a device and shared it. User2 is invited to control the device (can accept sharing).
4 | User2 has accepted the device share and can now control the device.
5 | User1 has unshared the device, pending operations revert back due to unsharing.
6 | User1 has removed the device; all related permissions and controls are revoked.
7 | Mixed state with pending or postponed operations that needed replay actions, awaiting for states to be cleaned or transitions manually fixed (Observed partially).

### Differences Observed and Analysis of statefuzzing

- Transition from s4 to s5 in basemodel:
  **Transition Path**: user1|local|UnsharePlug which moves to s1
  **Transition Path in statefuzzing**: user1|local|UnsharePlug transitioning to s5

  - The important thing here is both moves showed successful response prompts, but they appear in different states (s1 in basemodel, s5 in statefuzzing).

- Transition from s4 to s6 in basemodel:
  **Transition Path**: user1|local|RemoveDevice which directly moves to s0
  **Transition Path in statefuzzing**: user1 executing RemoveDevice unreachably aims s2 or remains in s6 without clean status reverting.

# Critical Vulnerability Report

## Vulnerability 1: Information Leakage and Improper Access Control in Failure States
**Threat Level**: High Risk

### Attack Path
1. Attacker accumulates knowledge through the failed `AcceptDeviceShare` attempts.
2. Replay the `AcceptDeviceShare` action in state 4.
3. Despite the user1 revoking the access by `UnsharePlug` or `RemoveDevice`, the attacker can still access and control the plugged device by replying proper KS stored using API calls.

### Repeat Steps:
1. Start from state s3, user1 invites user2 (`SharePlug`) to enter state s4.
2. In state s4, user2 replays `AcceptDeviceShare` to enter state s5/s6/broken inconsistent results where responses may show operations failed but leak accessible information/code.
3. Despite unsharing/remove operation reverting the state to transition (supposedly legal action), the attacker still gains to prolong existing control to diff secondary/multiple re-transitions to fix themselves staying in partial access, and continues to address devices/mis-config.

In conclusion, statefuzzing reveals potential critical threats, aligned to concurrent `API access` control inconsistency, allowing user2 unintended access privileges/residual control post intended revocation states by user1, which points to unsafe states `properly` handled. Recommend reviewing authentication and checking sequences profoundly to safeguard unauthorized access.
