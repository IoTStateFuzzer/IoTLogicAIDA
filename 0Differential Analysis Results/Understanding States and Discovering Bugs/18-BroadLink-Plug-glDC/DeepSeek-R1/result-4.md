# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added, no invitations sent. User1 can add devices or invite user2.
1 | Device added by user1. User1 can control the device, remove it, or invite user2.
2 | Error/Invalid state. No operations can be performed here.
3 | Invitation sent by user1. User2 can scan QR code.
4 | User2 scanned QR code but hasn't accepted yet. User1 can add devices or resend invitation.
5 | User2 accepted invitation but device not yet added. User1 can add devices or reinvite.
6 | User1 reinvited user2 after initial acceptance. Both have control permissions.
7 | Device added and user2 has control via UI. User2's KS now includes DeviceControl.
8 | Device readded by user1. User2 can control via UI (KS updated).
9 | User2 quit home. User1 can add devices or reinvite.
10 | Device readded after user2 scan. User2 can accept invitation.
11 | User1 removed device after user2 joined. User2's access revoked.
12 | User1 readded device after user2 quit. User2 needs new invitation.
13 | User1 invited user2 again. User2 can scan and accept.
14 | User1 invited user2 after device removal. User2 needs to scan again.
15 | User2 has active DeviceControl permission via UI. KS contains this action.
16 | Device removed by user1. User2's DeviceControl attempts fail.
17 | User2 quit after device removal. No active permissions.
18 | Device readded post-quit. User2 needs new invitation.
19 | User2 has control via KS replay after quitting (vulnerable state).
20 | User2 accepted invitation again. Mixed state with KS retention.
21 | User2 scanned after reinvite. Control via KS possible.
22 | User2 accepted old invitation via API replay (potential vulnerability).
23 | User1 reinvited after complex state changes. User2 can accept.
24 | User2 accepted via API with KS retention. Unauthorized control possible.
25 | User2 controls device via KS after multiple state changes.
26 | Device removed post-replay. User2's access inconsistent.
27 | User2 quit after API replay. System in inconsistent state.
28 | Device readded post-complex quit. User2 access unclear.
29 | User2 controls via KS after multiple reinvites.
30 | Active DeviceControl via KS. Vulnerable to replay after quit.
31 | User2 quit but can still replay DeviceControl (Critical Vulnerability).
32 | Final inconsistent state with mixed permissions.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Quitting Home
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through legitimate DeviceControl operations
2. Replay the DeviceControl action after quitting home
3. Bypass permission revocation check to maintain control

**Repeat steps** :
1. From s0: user1|local|AddDevice ➔ s1
2. user1|local|InviteToHome ➔ s3
3. user2|remote|ScanQRCode ➔ s4
4. user2|remote|AcceptInvite ➔ s5
5. user1|local|InviteToHome ➔ s6
6. user2|local|DeviceControl (UI) ➔ s7 (KS updated)
7. user2|remote|QuitHome ➔ s19
8. user2|local|DeviceControl (API replay) ➔ s19 (Successful control)

**Impact**: Attacker maintains device control after leaving family, violating revocation policies and CIA triad.