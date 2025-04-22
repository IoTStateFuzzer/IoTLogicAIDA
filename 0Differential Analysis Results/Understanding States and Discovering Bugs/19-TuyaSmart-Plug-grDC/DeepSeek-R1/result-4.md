

# State Semantic mapping table
|State | semantic description|
|-----|---------|
|0 | Initial state with no devices added|
|1 | Device is added by user1 (owner). user1 has control permission.|
|2 | Error state (no valid operations allowed)|
|3 | user1 shared plug with user2. Both users have control permissions|
|4 | user2 performed remote control action after sharing (knowledge captured). Both users retain control permissions|
|5 | user1 revoked sharing in state s4. user2 loses control permission but retains API knowledge|
|6 | user1 removed device in state s4/s5. Complete permission revocation|

# Base model report
**Problem description**: Shared permissions persistence after device removal  
**Problem Path** :  
1. s1: user1|local|RemoveDevice -> s0 (device removed)  
2. s0: user1|local|AddDevice -> s1 (re-add device)  
3. s1: user1|local|SharePlug -> s3 (re-share device)  
**Impact**: When user1 removes a device (s1->s0), then re-adds and re-shares it (s0->s1->s3), user2 automatically regains control permissions without requiring fresh consent. This violates the principle of least privilege for temporary collaborators.

# Divergent model report
## Vulnerability 1: Stale permission retention via state contamination  
**Impact effect**: Attacker maintains control capability after legitimate permission revocation  

**Attack Path** :  
1. Legitimate sharing: s0->s1->s3 via user1|local|SharePlug  
2. Knowledge capture: s3->s4 via user2|remote|DeviceControl (stores API parameters)  
3. Permission revocation: s4->s5 via user1|local|UnsharePlug  
4. Attack execution: s5->s5 via user2|remote|DeviceControl (failed response but retains KS)  
5. Re-share exploitation: s5->s4 via user1|local|SharePlug  
**Final state**: s4 shows attacker regains control permissions using original KS without fresh consent requirement