# Base Model
| State | Semantic Description                                                                                 |
|-------|------------------------------------------------------------------------------------------------------|
| 0     | Initial state.                                                                                      |
| 1     | Error state.                                                                                        |
| 2     | user1 has added the device once; user2 is not invited.                                              |
| 3     | user1 has added the device once; user2 is invited but has not accepted.                              |
| 4     | No device added; user2 is invited but has not accepted.                                             |
| 5     | user1 has added the device once; user2 scanned the invitation but has not accepted.                 |
| 6     | user1 has added the device once; user2 has accepted the invite and is a family member with control. |
| 7     | user1 has added the device once; user2 is re-invited and remains a family member with control.      |
| 8     | No device added; user2 is a family member with rights to control any future device.                 |
| 9     | No device added; user2 remains a family member with control of any future device.                   |
| 10    | No device added; user2 scanned the invitation but has not accepted.                                 |
| 11    | No device added; user2 was a family member but was removed and no longer has membership.            |
| 12    | user1 has added the device once; user2 was removed from the family and has no control.              |
| 13    | user1 has added the device once; user2 was a family member but is now removed and lacks control.    |
| 14    | user1 has added the device once; user2 was accepted but then removed from the family and lost control. |
| 15    | The device was removed; user2 was a family member but is now removed and has no device access.      |
| 16    | No device added; user2 was a family member but is now removed and has no control.                   |
| 17    | user1 has added the device once; user2 was removed from the family and scanning again did not restore membership. |
| 18    | user1 has added the device once; user2 was removed from the family and remains without membership.  |
| 19    | No device added; user2 was removed from the family and remains without membership.                  |
| 20    | user1 has added the device once; user2 accepted but then quit the family and no longer has membership. |
| 21    | user1 has removed and re-added the device; user2 is not a family member.                            |
| 22    | user1 removed then re-added the device; user2 was removed from the family and remains not a member. |
| 23    | user1 has re-added the device; user2 scanned a code but remains not a family member.                |
| 24    | user1 has re-added the device; user2 was a family member but is now removed and lacks membership.   |
| 25    | No device added; user2 accepted then quit the family and no longer has membership.                  |
| 26    | No device remains; user2 was accepted then removed from the family.                                 |
| 27    | No device remains; user2 was removed from the family and scanning again has no effect.             |
| 28    | user1 has re-added the device; user2 was removed from the family and is newly invited but hasn't accepted. |
| 29    | No device added; user2 was removed from the family and is re-invited but hasn't accepted.           |
| 30    | user1 has added the device once; user2 was removed from the family and is newly invited but hasn't accepted. |
| 31    | No device added; user2 was removed from the family and is newly invited but hasn't accepted.        |
| 32    | user1 has re-added the device; user2 was removed from the family and is newly invited but hasn't accepted. |
| 33    | No device added; user2 was re-invited and scanned but has not accepted.                             |
| 34    | user1 has added the device once; user2 was re-invited but has not accepted.                         |

