# State Semantic mapping table
State | semantic description
-----|---------
0 | Indicates the initial status.
1 | No changes and actions can perform for user1. Indicates a state where operations are not allowed for user1 to change the home or device status.
2 | Device removed by user1. Represents the state where operations to manage or control devices yield no results because the device is removed.
3 | user1 invites user2 to the home and user2 accepts the invitation. Both users now have control over the devices.
4 | user2 has control permissions temporarily due to user1's invitation; user2 can now attempt various actions.
5 | user1 retains device control; user2 retains device control knowledge after the invitation is reset.
6 | User1 removes the device, causing status transition and acknowledgment from the system.
7 | User1 removes user2 from home; user2's temporary control is revoked.
8 | Extended control scenarios where user1 keeps control, and user2, despite an invitation process, is likely in the knowledge phase waiting for future access.
9 | Continued control and device knowledge updates for user2, aimed at maintaining synchronization.
10 | Extended state for invitation and control where user2 retains the intent to regain control by knowing the device status and waiting for further exploitation.

# Critical Vulnerability report
## Vulnerability 1: Unauthorized Device Control Leak
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through obtaining device control states in state 4.
2. Replay the user2|remote|DeviceControl action in state 4.
3. Bypass the invitation removal by retaining the device control knowledge, transitioning to states 5+.

**Repeat steps** :
Starting from state s0, perform operation "user1|local|InviteAndAccept" to reach state s3, then perform action related to "user2|remote|DeviceControl" to transition to further states where user2 can replay control attempts (e.g., states s4, s5, s6).

This vulnerability highlights a possible leak in device control mechanisms, where an attacker user2 can keep controlling devices or maintain control knowledge even after attempting various attack steps, leveraging control actions, and exploiting the transition checks at multiple points.