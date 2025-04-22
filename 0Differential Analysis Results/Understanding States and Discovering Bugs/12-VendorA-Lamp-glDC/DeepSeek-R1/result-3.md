

# State Semantic mapping table
| State | Semantic Description |
|-------|-----------------------|
| 0     | Initial state: No devices added, no users invited. |
| 1     | Device added by user1. User2 has no permissions. |
| 2     | Error state: All actions return NoElement. |
| 3     | User2 invited and accepted (legitimate control permissions). |
| 4     | Device exists, user2 has legitimate control permissions. |
| 5     | Attacker (user2) has successfully controlled device locally once (KS filled). Both users can control. |
| 6     | Device removed by user1. Attacker retains KS but cannot control. |
| 7     | User2 removed from home by user1, but attacker still has KS and can control via API. |
| 8     | User2 removed, device removed. Attacker's control fails. |
| 9     | Device re-added, user2 not invited. Attacker's control fails. |
| 10    | User2 re-invited, legitimate permissions restored. |

# Base model report
Every thing is OK.

# Divergent model report
## Vulnerability 1: Persistent Control After Permission Revocation  
**Impact effect**: Attacker retains device control capability after being removed from the home.  
**Attack Path**:  
1. Legitimate invitation: s0 ➔ s3 ➔ s4 (user2 gains control permissions).  
2. Attacker executes local control: s4 ➔ s5 (KS populated).  
3. User1 removes attacker: s5 ➔ s7 via RemoveFromHome.  
4. Attacker replays "user2|local|DeviceControl" in s7 ➔ Success (retains control).  

*Security Impact*: Violates CIA triad (Integrity & Availability) - attacker maintains unauthorized control over the device.

## Vulnerability 2: State Contamination Through API Replay
**Impact effect**: API knowledge from previous valid sessions enables unauthorized state transitions.

**Attack Path** :
1. Knowledge acquisition:  
   s4 -> s5 ("user2|local|DeviceControl" success)
2. Replay attack:  
   s8 (removed state) -> s8 with "user2|local|DeviceControl" failure (limited impact)  
   s6 (device removed) -> s6 with failed replay (partial impact)