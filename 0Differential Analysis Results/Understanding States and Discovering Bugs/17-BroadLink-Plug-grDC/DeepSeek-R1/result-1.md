# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state: No devices added, no invitations sent.
1 | Device added by user1. User1 can control the device.
2 | Invalid/error state with no operational capabilities.
3 | Invitation initiated by user1 (QR generated). No device bound yet.
4 | user2 scanned invitation QR code (pre-acceptance).
5 | user2 accepted invitation but no device bound yet.
6 | user1 re-invited user2 after initial acceptance.
7 | user1 and user2 have device control (normal family sharing state).
8 | Device added after invitation acceptance. Both users have control.
9 | user2 quit home after device sharing. user1 needs to re-add device.
10 | Device added post-invitation scan (pre-acceptance state).
11 | Device added and invitation initiated (mixed state).
12 | user2 quit after device sharing. user1 maintains control.
13 | Multiple invitations handled with device present.
14 | Invitation re-initiated after device removal.
15 | Active sharing state with attacker's DeviceControl in KS.
16 | Device removed while attacker retains replay capability.
17-32 | Various persistence states where attacker maintains DeviceControl replay capability through state transitions even after legitimate revocation.

# Critical Vulnerability report
## Vulnerability 1: Persistent Device Control After Permission Revocation
**Threat Level** : High Risk

**Attack Path** :
1. Attackers accumulate knowledge through legitimate DeviceControl operations during valid sharing period
2. Replay the user2|remote|DeviceControl action in post-revocation states (e.g. s31)
3. Bypass the permission revocation check to maintain unauthorized control

**Repeat steps** :
1. From s0: user1 adds device → s1
2. user1 invites → s3
3. user2 scans QR → s4
4. user2 accepts invite → s5
5. user1 adds device → s8
6. user2 performs DeviceControl (stores in KS) → s30
7. user2 quits home → s31
8. Attacker replays DeviceControl in s31:
   - System returns successful control response
   - Attacker maintains device control despite revocation

## Vulnerability 2: State Desynchronization Attack
**Threat Level** : Medium Risk

**Attack Path** :
1. Attacker exploits state machine divergence between UI and API paths
2. Uses API replay in states where UI actions are restricted (e.g. s16)
3. Creates inconsistent permission states between users

**Repeat steps** :
1. From s15 (valid sharing state)
2. user1 removes device → s16
3. user2 replays DeviceControl via API:
   - System returns empty response instead of permission error
   - Leaks device existence information through response pattern