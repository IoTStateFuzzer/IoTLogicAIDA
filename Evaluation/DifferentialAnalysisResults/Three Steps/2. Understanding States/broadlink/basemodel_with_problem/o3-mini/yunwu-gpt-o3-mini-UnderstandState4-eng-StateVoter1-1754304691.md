# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0 | Initial state with no device added and no invitation initiated. |
| s1 | Error state. |
| s2 | user1 has added the device once; no permission-sharing invitation has been issued, so user2 has no access. |
| s3 | user1 added one device and sent an invitation to user2; the invitation is pending as user2 has not yet accepted. |
| s4 | user1 issued an invitation without adding a device; user2’s invitation remains pending. |
| s5 | user1 added one device and sent an invitation; user2 scanned the QR code but has not yet accepted, leaving the status pending. |
| s6 | user1 added one device and sent an invitation that user2 both scanned and accepted, establishing user2 as a family member with permanent control. |
| s7 | user1 added one device and issued two invitations (a duplicate reissue); after user2 accepted the later invitation, user2 is established as a family member. |
| s8 | Without any device added, user1’s invitation was scanned and accepted; user2 becomes a family member with permanent rights that will apply once a device is bound. |
| s9 | With no device added, user1 issued two invitations and user2 accepted the final one, thereby becoming a family member. |
| s10 | user1 sent an invitation (without adding a device) that user2 scanned but did not accept, so the invitation remains pending. |
| s11 | user1 sent an invitation that user2 accepted, but then revoked user2’s membership (RemoveFromHome); no device was added and access is revoked. |
| s12 | After an invitation was accepted and subsequently revoked, user1 added a device; however, user2 no longer holds any control. |
| s13 | user1 added a device and sent an invitation that was accepted, but later removed user2 from the family; the device remains active though user2’s access is revoked. |
| s14 | user1 added one device and obtained invitation acceptance from user2, but a later removal from the home revoked user2’s control rights. |
| s15 | user1 added a device and shared it with user2 (invitation accepted), then removed user2 and also removed the device—resulting in no bound device and no access for user2. |
| s16 | user1 issued an invitation (which user2 scanned and accepted) without adding a device; however, subsequent revocation leaves user2 without family membership. |
| s17 | user1 initially sent an invitation that was accepted and then revoked; after adding a device, a later QR scan by user2 initiated a new invitation that remains pending. |
| s18 | user1 added one device and sent an invitation that was accepted but later revoked; an extra QR scan by user2 starts a new invitation cycle, leaving user2 pending while the device remains active. |
| s19 | Without any device added, user1 sent an invitation that was accepted and then revoked; a subsequent QR scan left user2 in a pending state with no granted access. |
| s20 | user1 added one device and sent an invitation that was accepted, but user2 then voluntarily quit the home—so although the device remains, user2 relinquished family control. |
| s21 | user1 added a device and secured invitation acceptance from user2, but later revoked user2’s membership, removed the device, and then re-added it; as a result, user2 no longer has access. |
| s22 | user1 added one device and obtained invitation acceptance from user2, but subsequently revoked membership and removed the device before re-adding it; user2 does not retain control. |
| s23 | user1 added a device and completed an invitation flow (accepted then revoked), removed and re-added the device, and afterwards user2 scanned the QR code—yet without a new acceptance, user2 remains pending. |
| s24 | user1 sent an invitation that was accepted by user2, then later revoked (removing membership), and after that added a device; consequently, user2 loses control. |
| s25 | user1 issued an invitation without adding a device; although user2 accepted, user2 later quit the home, resulting in no access. |
| s26 | user1 added one device and sent an invitation that was accepted by user2, but then revoked the sharing and removed the device—leaving user2 without permission. |
| s27 | user1 added a device and initially completed the invitation flow (accepted by user2) which was then revoked and the device removed; a subsequent QR scan by user2 did not culminate in acceptance, so no access is granted. |
| s28 | user1 initially sent an invitation that was accepted then revoked, added a device, and subsequently re-issued a new invitation after a QR scan by user2; user2’s invitation is now pending acceptance. |
| s29 | Without any device added, user1 sent two invitations resulting in an initial acceptance that was later revoked; a subsequent QR scan started a new invitation, leaving user2 pending. |
| s30 | user1 added one device and sent an invitation that was accepted, but after revoking family membership, a later QR scan led to a new invitation—user2 remains pending acceptance. |
| s31 | user1 added a device and completed the invitation flow (accepted by user2) but then revoked sharing and removed the device; a subsequent QR scan and new invitation left user2 pending with no bound device. |
| s32 | user1 added a device and underwent an invitation cycle that was accepted then revoked; after removing and re-adding the device, a new invitation initiated by a QR scan leaves user2 pending acceptance. |
| s33 | Without any device added, user1 issued two invitation actions (with an intervening QR scan) and user2 remains in a pending state without acceptance. |
| s34 | user1 added one device and sent two invitations (with a QR scan in between); since user2 only scanned the QR code without final acceptance, the invitation remains pending. |


