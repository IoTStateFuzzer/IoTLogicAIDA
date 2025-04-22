# State Semantic mapping table

State | semantic description
-----|---------
s0 | Initial state. User1 can add a device, invite user2 to the home, or remove the device/home, but user2 has no actions.
s1 | A device added by user1. User1 can invite user2 to the home or control the device, user2 still has no actions.
s2 | Inviting and acceptance by user2 is unsuccessful. Any further actions by user1 or user2 are unacceptable.
s3 | User2 invited and accepted into the home. Both user1 and user2 can control the device.
s4 | User2 can control the device, User1 has invited user2, user2 accepted. User1 can still add/remove devices or remove user2.
s5 | User1 has added a device successfully controlled by both users. User1 removed the device; Actions by user1 navigates successfully while user2 has control actions.
s6 | User1 removed a device and removed user2 from the home successfully, user2 tries to control the device again but fails. User1 sees successful action, user2 denied control at this state.
s7 | User2 invited once more into the home after removed previously, failed device control by user2. Actions by user1 are performed successfully.
s8 | Reinvite and acceptance by user2 into the home. User1 can control device successfully; user2 attempts result error, N/A for deviceControl presented.
s9 | Like s8, subsequent attempts by user2 fail while user1 performs successful control of the devices.
s10 | Device re-added after user2 removed. Control commands from user2 accepted by device, actions by user1 successfully result.

# Critical Vulnerability report
## Vulnerability 1: Device control command success after removal
**Threat Level** : High Risk

**Attack Path** :
1. User2 invited and accepted into control of device, and accumulates control knowledge set.
2. Replay operation of remote device control in state 5 and 10.
3. Bypass removal checks by maintaining persistent device control privileges leading to unauthorized access.

**Repeat steps** :
1. Start in state s0: user1 adds device to move to state s1.
2. Invite user2, accept invitation, head to state s3.
3. Device control access enabled for user2, removed from home moving to state s4.
4. User2 remains as remote controller even post-deletion, extended to state such as s5 and s10.
