# State Semantic Mapping Table

| State | Semantic Description                                                                                                        |
|-------|-----------------------------------------------------------------------------------------------------------------------------|
| 0     | Initial state.                                                                                                              |
| 1     | User1 added a device to the home.                                                                                           |
| 2     | User1 removed the added device. No devices present at home.                                                                 |
| 3     | User1 invited and user2 accepted the invitation to the home. User2 now has full control over devices.                       |
| 4     | User1 has added a device, invited user2, and user2 has successfully accepted. User1 and user2 have control over the device. |
| 5     | User2 has attempted to control the device locally and has succeeded in controlling it.                                      |
| 6     | User1 removed the device, which user2 was controlling. User2 no longer has control over the device.                         |
| 7     | User1 removed user2 from the home. User2 no longer has access to the home and associated devices.                           |
| 8     | Intermediate state achieved when device is added, shared, and removed multiple times.                                       |
| 9     | User1 has successfully re-added and shared the device, and control is present with user2.                                   |
| 10    | User1 removed the device, added it back, and then shared it again successfully. User2 regained control of the device.       |

# Critical Vulnerability Report

## Vulnerability: User2 gaining unauthorized control of the device after its removal

**Threat Level**: High Risk

**Attack Path**:
1. **Attacker's Knowledge Set**:
   - Initially, user2 has no knowledge set (empty).
   - User2 gains control capabilities i.e., `user2|local|DeviceControl` by accepting the invitation.
2. **Exploit Path via Replay**:
   - User1 adds the device and invites user2 to the home.
   - User2 gains control (`user2|local|DeviceControl`) and performs local device control operations effectively.
   - User1 removes the device, logically expecting user2 to lose control (`state 6` or `state 8`).
   - However, the state machine indicates residual control knowledge allowing user2 to manipulate the device despite its claimed removal.
3. **Bypassing Control Removals**:
   - User removal and device removal do not eliminate the `user2` control capabilities which then are exploited by the attacker to maintain unauthorized controls.

**Repeat Steps**:
1. Transition to s5: 
   - From s0, perform `user1|local|AddDevice` to get into `s1`.
   - From s1, perform `user1|local|InviteAndAccept` to get into `s4`.
   - From `s4`, user2 performs `user2|local|DeviceControl` to reach `s5`.
2. Transition s5 to s10 via user1:
   - User1 initiated states such as `RemoveFromHome` execute successfully.
   - However, user2 utilizes residual knowledge (`s5 control` remains), repeatedly violating expected security controls leading to assurance breach.

# Comprehensive Assessment of basemodel

**Problem Description**:
1. **State Control Leak**: Once the invitation is accepted, user2 does not appropriately lose access upon device removal or even house removal.
2. **Violation Path**:
   - For the majority of transitions, we notice user2’s control signals implied and even executed despite the remedial access control efforts by user1.

Summary concludes:
- Persistent injection replay potential in various intermediary states (`s4, s5, s10, etc.`)
- Control violations and leaks left an exploitable path via state transitions.
- Intrusion countermeasure strategies and more dynamic validation checks proposed at invitation, control, and removal phases.