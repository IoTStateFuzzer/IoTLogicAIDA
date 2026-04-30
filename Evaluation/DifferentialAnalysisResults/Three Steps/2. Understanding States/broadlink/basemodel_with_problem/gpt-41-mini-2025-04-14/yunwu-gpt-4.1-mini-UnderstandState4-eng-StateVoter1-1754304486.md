# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| 0     | Initial state. user1 has not added any device; user2 is not invited or recognized. |
| 1     | Error state due to invalid or undefined action sequence. |
| 2     | user1 has added the device once; user2 is not invited and has no control permissions. |
| 3     | user1 added the device once and invited user2 as a family member; user2 has been invited but has not accepted yet and holds no control. |
| 4     | user1 invited user2 as a family member without adding any device; user2 is invited but has not accepted yet and holds no control. |
| 5     | user1 added the device once and invited user2 as a family member; user2 scanned the invitation but has not accepted yet and thus has no control. |
| 6     | user1 added the device once and invited user2 as a family member; user2 scanned and accepted the invitation, becoming a family member with permanent control over user1’s devices. |
| 7     | user1 added the device once and invited user2 twice as a family member; user2 scanned and accepted, holding permanent family membership and control. |
| 8     | user1 invited user2 as a family member without device addition; user2 scanned and accepted the invitation, gaining family membership with control privileges despite no device added. |
| 9     | user1 invited user2 twice as a family member without device addition; user2 scanned and accepted, holding family membership and control rights. |
| 10    | user1 invited user2 as a family member; user2 scanned the invitation but has not accepted yet, and no device is currently added. |
| 11    | user1 invited user2 as a family member, user2 accepted, then user1 removed user2 from family; user2 lost family membership and control. |
| 12    | user1 removed user2 from family membership, then added the device once; user2 is not family member and has no permissions. |
| 13    | user1 added the device once, invited and user2 accepted as family member, then user1 removed user2; user2 lost family membership and control despite device added. |
| 14    | user1 added the device once, invited and user2 accepted as family member, then user1 removed user2; user2 no longer has family membership or control. |
| 15    | user1 added the device once, invited and user2 accepted as family member, then removed user2 and removed the device; user2 has no privileges and device is removed. |
| 16    | user1 invited user2 as family member, user2 accepted, then user1 removed user2; no device added and user2 holds no permissions. |
| 17    | user1 removed user2 from family, re-added device once, user2 scanned new invitation but has not accepted; user2 is not a family member and holds no control. |
| 18    | user1 removed user2, then user2 scanned invitation after removal but has not accepted; device is added once; user2 has no family membership or control. |
| 19    | user1 removed user2 from family, user2 scanned invitation after removal without acceptance; no device currently added; user2 holds no family membership or control. |
| 20    | user1 added the device once, user2 accepted family membership, then user2 quit family voluntarily; user2 lost family membership and control but device remains added. |
| 21    | user1 removed user2 from family, removed the device, then re-added the device once; user2 has no family membership or permissions. |
| 22    | Same as state 21: user1 re-added device after removing user2 and device; user2 does not have family membership or control. |
| 23    | User1 re-added the device once after removal; user2 scanned new invitation but has not accepted yet; user2 has no family membership or control. |
| 24    | user1 invited user2, user2 accepted family membership, then user1 removed user2; after removing user2, user1 added device once; user2 holds no family membership or control. |
| 25    | user1 invited user2 and user2 accepted, then user2 quit family membership voluntarily; no device added; user2 does not have family membership or control. |
| 26    | user1 removed user2 from family and removed device after invitation and acceptance; no device added and user2 holds no permissions. |
| 27    | user2 scanned invitation but did not accept after user1 removed user2 and device; user2 has no family membership or control. |
| 28    | user1 removed user2 from family, re-added device once, reinvited user2, who scanned new invitation but has not accepted yet; user2 holds no family membership or control currently. |
| 29    | user1 removed user2, reinvited user2, who scanned invitation but not accepted currently; no device added; user2 holds no family membership or control. |
| 30    | user1 removed user2, re-added device once, reinvited user2, who scanned invitation but has not accepted; user2 holds no family membership or control. |
| 31    | user1 removed user2 and device, re-added device once, reinvited user2, who scanned invitation but has not accepted; no family membership or control for user2. |
| 32    | user1 removed user2 and device, re-added device once, reinvited user2, who scanned invitation but has not accepted; user2 has no family membership or control. |
| 33    | user1 invited user2 twice as family member without adding device; user2 scanned invitation but has not accepted; user2 does not hold family membership or control. |
| 34    | user1 added device once and invited user2 twice as family member; user2 scanned invitation but has not accepted; user2 holds no family membership or control. |

