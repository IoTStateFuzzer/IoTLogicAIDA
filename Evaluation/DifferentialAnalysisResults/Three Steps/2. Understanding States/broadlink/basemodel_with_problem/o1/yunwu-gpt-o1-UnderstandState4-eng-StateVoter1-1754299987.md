# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0  | Initial state. |
| 1  | Error state. |
| 2  | user1 has added the device once; user2 is not invited (no membership or privileges). |
| 3  | user1 has added the device once; user2 is invited but has not accepted. |
| 4  | No device added; user2 is invited but has not accepted. |
| 5  | user1 has added the device once; user2 scanned the invitation but has not accepted. |
| 6  | user1 has added the device once; user2 is a family member with permanent control. |
| 7  | user1 has added the device once; user2 is a family member with permanent control (possibly after re-invite). |
| 8  | No device added; user2 is a family member with permanent control for any future device. |
| 9  | No device added; user2 is a family member with permanent control (possibly after re-invite). |
| 10 | No device added; user2 scanned the invitation but has not accepted. |
| 11 | No device is present; user2 was a family member but is now removed from home (membership revoked). |
| 12 | user1 has added the device once; user2 was removed from home and is no longer a family member. |
| 13 | user1 has added the device once; user2 was a family member but was removed and no longer has control. |
| 14 | user1 has added the device once; user2 was a family member but is now removed from home (no control). |
| 15 | user1 previously added and then removed the device; user2 is not a family member. |
| 16 | No device; user2’s membership was revoked (removed from home). |
| 17 | user1 has added the device once; user2 was removed from home and scanning again does not restore membership. |
| 18 | user1 has added the device once; user2 was previously a member but is now removed, and rescanning did not restore membership. |
| 19 | No device added; user2 was removed from home and rescanning does not restore membership. |
| 20 | user1 has added the device once; user2 was a family member but quit the home and lost membership. |
| 21 | user1 has re-added the device (one device total); user2 is not a family member. |
| 22 | user1 has re-added one device; user2 is not a family member. |
| 23 | user1 has one device; user2 is not a family member, and scanning does not restore membership. |
| 24 | user1 has added the device once; user2’s membership was revoked and remains without membership. |
| 25 | No device added; user2 joined and then quit the home, so is not a member. |
| 26 | No device is currently added; user2’s membership was revoked. |
| 27 | No device is present; user2 was removed from home and scanning again did not restore membership. |
| 28 | user1 has added the device once; user2 is newly (re-)invited but has not accepted. |
| 29 | No device added; user2 is newly invited but has not accepted. |
| 30 | user1 has one device; user2 is newly (re-)invited but has not accepted. |
| 31 | No device added; user2 is newly re-invited but has not accepted. |
| 32 | user1 has one device; user2 is newly invited but has not accepted. |
| 33 | No device added; user2 is invited but has not accepted. |
| 34 | user1 has one device; user2 is invited but has not accepted. |

