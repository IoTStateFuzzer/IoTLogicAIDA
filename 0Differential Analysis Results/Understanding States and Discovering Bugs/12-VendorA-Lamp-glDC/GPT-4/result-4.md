# State Semantic mapping table
State | semantic description
-----|---------
0 | Indicates the initial status, no device added, no user invited.
1 | A device has been added by user1, but no user has been invited.
2 | No device has been added, and no user has been invited.
3 | A device has been added by user1, and user2 has been invited and accepted the invitation.
4 | No device has been added, but user2 has been invited and accepted the invitation.
5 | A device has been added by user1, user2 has been invited and accepted the invitation, and user2 has performed a device control operation.
6 | A device has been added by user1, user2 has been invited and accepted the invitation, and the device has been removed by user1.
7 | User2 has been removed from home by user1 after being invited and accepted the invitation.
8 | User2 has been removed from home by user1 after being invited and accepted the invitation, and the device has been removed by user1.
9 | A device has been added by user1, user2 has been invited and accepted the invitation, user2 has been removed from home by user1, and user2 has attempted to control the device but failed.
10 | A device has been added by user1, user2 has been invited and accepted the invitation, user2 has performed a device control operation, and user2 has been removed from home by user1.

# Critical Vulnerability report
## Vulnerability 1: Unauthorized Device Control
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through user2|local|DeviceControl
2. Replay the user2|local|DeviceControl action in state 5
3. Bypass the user1|local|RemoveFromHome check to enter privilege state 10

**Repeat steps** :
Starting from state s0, perform user1|local|AddDevice to reach state s1, perform user1|local|InviteAndAccept to reach state s4, perform user2|local|DeviceControl to reach state s5, perform user1|local|RemoveFromHome