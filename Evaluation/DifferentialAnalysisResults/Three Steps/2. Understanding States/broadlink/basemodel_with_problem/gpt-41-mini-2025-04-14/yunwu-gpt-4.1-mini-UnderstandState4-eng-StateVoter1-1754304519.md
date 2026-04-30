# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| 0     | Initial state. |
| 1     | Error state. |
| 2     | user1 has added the device once; user2 is not invited, not a family member, and has no control permissions. |
| 3     | user1 added the device once and invited user2 as a family member; user2 has not yet accepted the invitation. |
| 4     | user1 invited user2 as a family member without adding the device; user2 has not accepted the invitation. |
| 5     | user1 added the device once and invited user2 as a family member; user2 scanned the invitation QR code but has not accepted yet. |
| 6     | user1 added the device once and invited user2 as a family member; user2 accepted the invitation and now holds permanent family member status with control over all user1 devices. |
| 7     | user1 added the device once and invited user2 twice as a family member; user2 accepted and has permanent family member control rights. |
| 8     | user1 invited user2 as a family member without adding the device; user2 accepted and is a family member but has no device added. |
| 9     | user1 invited user2 twice as a family member without device added; user2 accepted and holds family membership but no device control. |
| 10    | user1 invited user2 as a family member without device added; user2 scanned the QR code invitation but has not accepted yet. |
| 11    | user1 invited user2 as a family member twice; user2 accepted but was removed from family membership; user2 no longer has family status or control; no device added. |
| 12    | user1 removed user2 from family membership, then added the device once; user2 is no longer family and has no control permissions. |
| 13    | user1 added device once, invited user2 twice as family, user2 accepted, then user1 removed user2; user2 lost family membership and device control. |
| 14    | user1 added device once, invited user2 once as family, user2 accepted, then user1 removed user2; user2 no longer family and has no control. |
| 15    | user1 added device once, user2 accepted family invitation, then user1 removed user2 and removed the device; no device is present and user2 has no permissions. |
| 16    | user1 invited user2 as family, user2 accepted, then user1 removed user2; no device added; user2 has no family membership or control. |
| 17    | user1 removed user2 from family, then added the device once; user2 scanned the new invitation QR code but has not accepted; user2 currently has no permissions. |
| 18    | user1 added device once, invited user2 twice as family, user2 accepted, then user1 removed user2; user2 scanned QR code again but has not accepted the new invite; no control granted. |
| 19    | user1 invited user2 twice, user2 accepted first invite, user1 removed user2; user2 scanned a new QR code but has not accepted; no device added and no control. |
| 20    | user1 added device once, invited user2 as family, user2 accepted then voluntarily quit family; user2 lost control permissions but the device remains added. |
| 21    | user1 removed user2 and device after acceptance; then re-added the device once; user2 is not family and has no control. |
| 22    | user1 removed user2 and device; user1 re-added device once but has not reinvited user2; user2 has no family membership or control. |
| 23    | user1 removed user2 and device; user1 re-added device once and re-invited user2; user2 scanned QR code but has not accepted; user2 currently has no control permissions. |
| 24    | user1 invited user2 as family, user2 accepted, user1 removed user2; then user1 added device once; user2 no longer family and has no device control. |
| 25    | user1 invited user2 as family without device added; user2 accepted then quit family; user2 has no permissions or device control. |
| 26    | user1 added device once, invited user2 as family who accepted; user1 then removed user2 and device; user2 has no family membership or device control. |
| 27    | user1 removed user2 and device; user2 scanned QR code again but has not accepted the new invite; no permissions granted and no device present. |
| 28    | user1 invited user2 twice as family, user2 accepted, user1 removed user2, added device once, re-invited user2; user2 scanned QR code but has not accepted the reinvitation; no control. |
| 29    | user1 invited user2 twice as family, user2 accepted first invite; user1 removed user2; user2 scanned QR code again but did not accept; no control permissions and no device added. |
| 30    | user1 added device once, invited user2 twice as family, user2 accepted, user1 removed user2; user2 scanned QR code but has not accepted the new invite; no control. |
| 31    | user1 added device once, invited user2 twice, user2 accepted, user1 removed user2 and device; user2 scanned QR code again and was reinvited but has not accepted; no device and no control. |
| 32    | user1 added device once, invited user2 twice, user2 accepted, removed user2 and device; re-added device once; user2 scanned QR code and was reinvited but has not accepted; no control. |
| 33    | user1 invited user2 twice as family without device added; user2 scanned QR code but has not accepted; user2 has no permissions or control. |
| 34    | user1 added device once, invited user2 twice as family; user2 scanned QR code but has not accepted; user2 has no control permissions despite device being added. |

