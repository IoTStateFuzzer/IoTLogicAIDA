# State Semantic mapping table
State | semantic description
-----|---------
0 | Indicates the initial status, no device added, no user invited.
1 | User1 has added a device, but no user has been invited.
2 | User1 has removed the device, no user has been invited.
3 | User1 has invited User2 and User2 has accepted the invitation, but no device has been added.
4 | User1 has added a device and invited User2, User2 has accepted the invitation.
5 | User1 has added a device and invited User2, User2 has accepted the invitation. User2 has also performed a device control operation.
6 | User1 has removed the device while User2 has control over the device.
7 | User1 has removed User2 from the home while User2 has control over the device.
8 | User1 has removed User2 from the home and the device while User2 has control over the device.
9 | User1 has added a device and removed User2 from the home while User2 has control over the device.
10 | User1 has added a device, invited User2, and User2 has accepted the invitation. User2 has also performed a device control operation.

# Critical Vulnerability report
## Vulnerability 1: Unauthorized Device Control
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through device control operation when they have been invited and accepted into the home.
2. Replay the device control action in state 6 after the device has been removed by User1.
3. Bypass the device control check to enter privilege state 6.

**Repeat steps** :
Starting from state s0, perform operation "user1|local|AddDevice" to reach state s1, then perform operation "user1|local|InviteAndAccept" to reach state s4, then perform operation "user2|local|DeviceControl" to reach state s5, and finally perform operation "user1|local|RemoveDevice" to reach state s6. In state s6, User2 can still control the device even though the device has been removed by User1. This is a security vulnerability