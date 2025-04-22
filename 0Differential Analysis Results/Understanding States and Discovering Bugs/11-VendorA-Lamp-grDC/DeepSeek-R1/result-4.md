

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state with no devices added and no users invited
1 | Device added by user1, no shared permissions
2 | Error/Invalid state (likely device removed)
3 | user2 successfully invited to home by user1 (no device present)
4 | user1 has device and user2 is invited member (user2 has home-level access)
5 | user2 has active control permissions through valid invitation
6 | Device removed by user1, but user2 remains in home
7 | user2 removed from home by user1 (access revoked)
8 | Device removed after user2 was in home (intermediate state)
9 | Device re-added after removal, user2 still in home
10 | Active state with device and valid user2 home membership

# Critical Vulnerability report
## Vulnerability 1: Information Exposure Through Error Codes
**Threat Level** : Medium Risk

**Attack Path** :
1. Attacker monitors error responses during device control attempts
2. Distinguishes between "device not found" (500000404) and "unauthorized" (500000401) errors
3. Determines system state (device existence vs permission status)

**Repeat steps** :
1. From s5 (valid access): user1 removes device ➔ s6
   - user2|remote|DeviceControl returns 500000404 (device status exposed)
2. From s5: user1 removes user2 ➔ s7 
   - user2|remote|DeviceControl returns 500000401 (permission status exposed)

**Security Impact**:
Different error codes reveal whether:
- Target device still exists in the system (404)
- Attacker's permissions were revoked (401)
This violates confidentiality by exposing system state information through error messages.

## Vulnerability 2: Stale Permission Cache in Re-Added Devices
**Threat Level** : Low Risk

**Attack Path** :
1. user1 adds device ➔ invites user2 ➔ removes device
2. user1 re-adds same device
3. user2 regains access without re-validation

**Repeat steps** :
s0 ➔ AddDevice(s1) ➔ Invite(s4) ➔ user2 controls(s5) ➔ RemoveDevice(s6) ➔ AddDevice(s10) ➔ user2 controls(s5)

**Security Impact**:
While technically correct (user2 remains in home), this could allow access to new devices without explicit re-authorization. Depends on whether device re-addition should require permission reaffirmation.