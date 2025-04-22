# State Semantic mapping table
State | semantic description
-----|---------
0 | Indicates the initial status, no device is added and no user is invited.
1 | User1 has added a device, but no user is invited.
2 | User1 has removed the device, and no user is invited.
3 | User1 has invited user2, but no device is added.
4 | User1 has added a device and invited user2.
5 | User1 has added a device and invited user2. User2 has control of the device.
6 | User1 has removed the device after user2 gained control of it.
7 | User1 has removed user2 from the home after user2 gained control of the device.
8 | User1 has removed user2 from the home and the device after user2 gained control of it.
9 | User1 has added a device and invited user2 after removing user2 from the home and the device.
10 | User1 has added a device and invited user2. User2 has control of the device after being removed from the home and the device.

# Critical Vulnerability report
## Vulnerability 1: Unauthorized Device Control
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through user1|local|DeviceControl
2. Replay the user2|local|DeviceControl action in state 4
3. Bypass the user1|local|RemoveFromHome check to enter privilege state 5

**Repeat steps** :
Starting from state s0, perform operation user1|local|AddDevice to reach state s1, perform operation user1|local|InviteAndAccept to reach state s4, and then perform operation user2|local|DeviceControl to reach state s5.