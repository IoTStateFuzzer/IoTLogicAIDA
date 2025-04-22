# State Semantic mapping table

State | semantic description
-----|---------
0 | Initial state, where no device control or permissions have been granted yet.
1 | User1 has added a device successfully; no changes in permissions for either user yet.
2 | User2 has no permissions to control devices; User1 can still manage devices but no shared permissions yet.
3 | User1 invites User2 to the family; User2 can accept the invite, but no permissions yet granted.
4 | User2 has been invited successfully and can now control the devices remotely, but no permanent permissions granted.
5 | User2 has successfully accepted the invitation; now both users can control devices. The permissions are still temporary, and the shared device control is valid until revoked.
6 | User2 has been successfully re-invited into the family group. Device control is still active for both users; User2 can control devices.
7 | User2 has successfully been re-invited and retains control over the devices.
8 | User2 has accepted another invitation; no new permissions granted, but temporary control over devices is retained.
9 | User2 has accepted the invitation, control is granted, but device removal/re-adding has not affected User2's control permissions yet.
10 | User2 can now manage devices; the invitation process was successful, but User2 cannot control devices without permission from User1.
11 | User2 is fully integrated into the family group and can control devices as part of the shared access, though permissions are still temporary.
12 | User2's permission status changes; they can control devices, but certain operations are now restricted.
13 | User2 can attempt to control devices, but not all actions are available, based on permissions granted by User1.
14 | User1 retains control over devices and can invite or revoke User2’s control, but User2's control is still temporary.
15 | User2 has the ability to control devices locally, but the operations performed by User1 and User2 are still restricted to specific devices and actions.
16 | User1 has full control over the devices, but User2 has restricted permissions to perform actions unless explicitly invited or re-permissioned.
17 | User2 can control devices locally; the status of the permissions has been restricted by User1’s actions.
18 | User2 can attempt to manage devices remotely; operations are still controlled by User1’s permissions and device configurations.
19 | User1’s remote control works, while User2’s operations have been limited or blocked.
20 | User2 can still attempt to manage devices, but the permissions are either absent or ineffective due to restrictions from User1.
21 | User1’s remote control permissions are intact, while User2’s remote permissions are still limited.
22 | User1 retains control over devices; operations for User2 are blocked or restricted.
23 | User2’s control is limited; they can attempt operations but have no real control due to lack of permissions.
24 | User2’s control is further restricted, making their actions ineffective in controlling devices.
25 | User2 can still try to control devices, but most actions are blocked based on the permission status.
26 | User2’s ability to control devices is still restricted, with no ability to bypass security checks or gain access.
27 | User2's permissions remain limited, and no new permissions are granted unless explicitly confirmed by User1.
28 | User2 cannot execute any new operations; all actions are still based on temporary permissions.
29 | User2’s permissions are restricted to certain actions; User1 controls the majority of device settings.
30 | User2 is blocked from controlling devices remotely; actions are only valid under certain conditions.
31 | User2’s permissions remain restricted with most actions being blocked unless authorized by User1.
32 | User2 can still access device control in specific conditions, but their permissions are largely invalid or ineffective.

---

**Critical Vulnerability Report**

## Vulnerability 1: Abnormal Access after Invitation Revocation
**Threat Level**: High Risk

**Attack Path**:
1. Attackers accumulate knowledge through accepting invitations multiple times.
2. Replay the `user2|remote|AcceptInvite` action in state 0.
3. Bypass the permission revocation by re-entering the family through the invitation process without being properly authenticated.

**Repeat steps**:
Starting from state s0, perform operation `user1|local|InviteToHome`, then transition to state s5, and user2 can again legally accept the invitation in state s5 despite being previously revoked from controlling devices.