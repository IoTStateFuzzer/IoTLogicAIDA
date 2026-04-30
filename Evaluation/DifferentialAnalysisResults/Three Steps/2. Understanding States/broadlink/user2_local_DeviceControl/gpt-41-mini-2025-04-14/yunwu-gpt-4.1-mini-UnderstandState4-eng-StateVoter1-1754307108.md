# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0    | Initial state. No device added by user1; user2 has no invitations or permissions. |
| s1    | user1 added the device once; user2 is not invited and has no control permissions. |
| s2    | Error state due to invalid sequence or operation. |
| s3    | user1 added the device once and invited user2 as a family member; user2 invitation is pending acceptance; user2 has no control permissions yet. |
| s4    | user1 invited user2 as a family member without adding the device; user2 invitation is pending acceptance; no control permissions granted. |
| s5    | user1 added the device once and invited user2 as a family member; user2 scanned the invitation (e.g., QR code) but has not accepted yet; user2 has no control permissions. |
| s6    | user1 added the device once; user2 accepted the family invitation and is a family member with permanent control rights over all user1 devices, regardless of device addition count. |
| s7    | user1 added the device once and re-invited user2 as family member; user2 accepted; user2 remains family member with permanent control rights over all user1 devices. |
| s8    | user1 invited user2 as a family member without adding the device; user2 accepted the invitation and became family member with permanent control rights over all user1 devices despite no device added. |
| s9    | user1 invited user2 twice as family member without device addition; user2 accepted and holds permanent control rights as family member. |
| s10   | user1 invited user2 as a family member without device addition; user2 scanned invitation but has not accepted yet; user2 has no control permissions. |
| s11   | user1 added the device once; user2 accepted family invitation but then quit the family home; user2 lost family membership and associated permanent control permissions. |
| s12   | user1 invited user2 as a family member without device added; user2 accepted but then quit the family home; user2 no longer holds family membership or control permissions. |
| s13   | user1 invited user2 twice as a family member without device added; user2 scanned invitation but has not accepted; user2 has no control permissions. |
| s14   | user1 added the device once; user1 invited user2 twice as family member; user2 scanned the second invitation but has not accepted; user2 currently has no control permissions. |

# Divergent Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0    | Initial state with no devices added, and user2 has no invitation or permissions. |
| s1    | user1 has added the device once; user2 is neither invited nor a family member and has no control permissions. |
| s2    | Error state. |
| s3    | No device added; user1 has invited user2 to become a family member, but user2 has not scanned or accepted the invitation yet; user2 has no control. |
| s4    | No device added; user2 has scanned the invitation QR code but has not accepted the family member invitation; user2 has no control. |
| s5    | No device added; user2 has scanned and accepted the family member invitation; user2 is a family member with permanent control rights over all user1 devices, despite no device being added yet. |
| s6    | No device added; user1 has invited user2 multiple times; user2 scanned and accepted the family member invitation once; user2 is a family member with permanent control rights. |
| s7    | user1 added the device once; user1 invited user2 multiple times; user2 scanned and accepted; user2 is a family member with permanent control rights over all user1 devices. |
| s8    | user1 added the device once; user2 invited once, scanned, and accepted the family member invitation; user2 is a family member with permanent control rights. |
| s9    | No device added; user2 accepted family membership and later quit the family; user2 is no longer a family member and has no control permissions. |
| s10   | user1 added the device once; user1 invited user2; user2 scanned but has not accepted the invitation; user2 is not a family member and has no control. |
| s11   | user1 added the device once; user2 invited but has neither scanned nor accepted; user2 is not a family member and has no control. |
| s12   | user1 added the device once; user2 accepted the family member invitation then quit the family; user2 no longer has membership or control. |
| s13   | user1 added the device once; user1 invited user2 multiple times; user2 scanned once but has not accepted the latest invitation; user2 is not a family member and has no control. |
| s14   | No device added; user1 invited user2 twice; user2 scanned once but has not accepted the latest invitation; user2 is not a family member and has no control. |
| s15   | user1 added the device once; user1 invited user2 twice; user2 scanned, accepted, and currently controls the device as a family member with permanent control rights. |
| s16   | user1 added the device once then removed it; user2 is an accepted family member with permanent control rights but currently no device to control. |
| s17   | user1 removed the device; user2, who previously accepted family membership and controlled the device, quit the family after removal; user2 no longer has membership or control. |
| s18   | user1 removed then re-added the device once; user2 quit the family and has no current membership or control rights. |
| s19   | user1 added the device once; user2 accepted family membership and controlled device but quit later; user2 no longer has membership or control. |
| s20   | user1 added the device once; user2 quit family membership and scanned a new invitation but has not accepted; user2 has no membership or control. |
| s21   | user1 removed then re-added the device once; user2 quit family, scanned again, but has not accepted; user2 has no membership or control. |
| s22   | user1 removed the device; user2 quit family, scanned again without acceptance; user2 has no membership or control; no device currently bound. |
| s23   | user1 removed the device and re-invited user2; user2 scanned again but has not accepted; user2 has no membership or control; no device currently bound. |
| s24   | user1 removed and re-added the device; user2 quit family, rescanned, and was reinvited but has not accepted; user2 has no control. |
| s25   | user1 added the device once; user2 quit family, rescanned, was reinvited, but has not accepted; user2 has no control or membership. |
| s26   | user1 added the device once; user2 accepted the family member invitation and controls the device; after device removal, user2 remains family member with permanent control rights but no device to control. |
| s27   | user1 removed the device; user2 accepted family membership previously but quit the family after removal; user2 no longer has membership or control. |
| s28   | user1 removed and re-added the device; user2 quit family membership; user2 has no current control or membership. |
| s29   | user1 removed then re-added the device once; user2 accepted family membership but quit before the second device addition; user2 has no current membership or control. |
| s30   | user1 added the device once; user2 accepted family membership and currently has device control rights. |
| s31   | user1 added the device once; user2 accepted family membership but quit later; user2 no longer has membership or control. |
| s32   | user1 removed then re-added the device once; user2 accepted family membership and retains permanent control rights despite device removal and re-addition. |

