# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| 0     | Initial state. No device added, no permission sharing or invitations issued. |
| 1     | Error state. Invalid or inconsistent sequence of actions detected. |
| 2     | user1 added the device once; user2 is not invited and has no permissions. |
| 3     | user1 added the device once and invited user2 as a family member; user2 has not accepted the invitation yet and thus has no control. |
| 4     | user1 invited user2 as a family member without adding the device; user2 has not accepted yet and has no control. |
| 5     | user1 added the device once and invited user2; user2 scanned the QR code but has not accepted the invitation, so no control is granted. |
| 6     | user1 added the device once and invited user2; user2 scanned the QR code and accepted, becoming a family member with permanent control over all user1’s devices. |
| 7     | user1 added the device once and invited user2 twice; user2 accepted one invitation and is a family member with permanent control over all user1’s devices. |
| 8     | user1 invited user2 as a family member without adding the device; user2 scanned QR and accepted, becoming family member with permanent control over all devices, though no device instance is currently added. |
| 9     | user1 invited user2 twice as a family member without device added; user2 accepted an invitation and has permanent family member control despite no device present. |
| 10    | user1 invited user2 as a family member; user2 scanned QR but did not accept yet; no device added and no control granted. |
| 11    | user1 invited user2 twice as family member; user2 accepted; then user1 revoked user2’s family membership, revoking all permissions and control; no device added. |
| 12    | user1 removed user2’s family membership, then added the device once; user2 is not family member and has no control. |
| 13    | user1 added the device once, invited user2 twice, user2 accepted one invite, then user1 revoked user2’s family membership; user2 has no control despite device presence. |
| 14    | user1 added device once, invited and user2 accepted, then revoked user2’s family membership; user2 loses all control, device remains added. |
| 15    | user1 added device once, invited user2 who accepted, then revoked user2’s membership and removed the device; user2 has no control and no device present. |
| 16    | user1 invited user2 who accepted, then revoked user2’s family membership; no device added and user2 has no control. |
| 17    | After revocation of family membership and device re-addition by user1, user2 rescanned QR but has not accepted again; user2 has no membership or control. |
| 18    | Same as state 17; user2 rescanned QR after revocation and device add, but no acceptance; no control granted. |
| 19    | user1 invited user2 twice without device added; user2 accepted but was removed from family; rescanned QR without acceptance; no control. |
| 20    | user1 added device once, invited user2 who accepted, then user2 voluntarily quit family; user2 loses permanent control of all devices. |
| 21    | user1 removed user2’s family membership and removed the device, then re-added device once; user2 is not family and has no control. |
| 22    | Same as state 21, with additional invites before removal; user2 is no longer family member or controller after removal. |
| 23    | user1 removed user2 from family and device, re-added device once, user2 rescanned QR but did not accept; no control granted. |
| 24    | user1 invited and user2 accepted, then user1 removed user2 from family and added device once; user2 is not family member and has no control. |
| 25    | user2 accepted family invitation but voluntarily quit family; no device added; user2 has no control. |
| 26    | user1 added device once, invited user2 who accepted, then removed user2 from family and removed device; user2 has no control and no device present. |
| 27    | Same as 26 with user2 rescanning QR after removal and device deletion; no acceptance, no control granted. |
| 28    | user1 invited user2 twice, user2 accepted, then user1 revoked membership and added device; user2 rescanned QR and was reinvited but has not accepted new invitation; no control. |
| 29    | Same as 28 but user1 invited user2 again without device added; user2 invited but not yet accepted; no control granted. |
| 30    | user1 added device once, invited user2 twice, user2 accepted, then user1 revoked and re-invited user2; user2 invited but not accepted new invitation; no control. |
| 31    | user1 revoked user2 and removed device, then re-invited user2 who rescanned QR but not accepted; no device present and no control. |
| 32    | user1 revoked user2 and device, re-added device once, reinvited user2 who rescanned QR but not accepted yet; no control. |
| 33    | user1 invited user2 twice as family without device added; user2 rescanned QR but has not accepted; no control granted. |
| 34    | user1 added device once, invited user2 twice as family; user2 rescanned QR but has not accepted; no control granted. |

