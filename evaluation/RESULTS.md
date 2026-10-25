# SignalQuarry evaluation results

Synthetic evaluation set built independently of the demo generator (`evaluation/build_evaluation_data.py`): 1,875 rows, 45 scripted cases plus a week of background traffic. Expected alerts were written by hand from the documented rules, not copied from SignalQuarry output.

How to read the counts:

- **Expected** - alerts the ground truth says SignalQuarry must raise.
- **Generated** - every alert SignalQuarry actually raised, wanted or not.
- **Matched** - generated alerts that were expected (same rule and same key: the source IP for LL-001, the account for the other rules). Severity and evidence count are checked on matched alerts, so a matched alert can still have the wrong severity.
- **Missed** - expected alerts that were not generated.
- **Unexpected** - generated alerts that were not expected.

Every run reconciles: expected = matched + missed, and generated = matched + unexpected. Precision is matched / generated; recall is matched / expected.

## Run: exact duplicate rows kept

1,875 rows read, 1,875 events analysed, 43 alerts generated.

| Measure | Result |
|---|---|
| Expected alerts | 41 |
| Total alerts generated | 43 |
| Correctly matched alerts | 41 |
| Missed expected alerts | 0 |
| Unexpected alerts | 2 |
| Precision (matched / generated) | 95.3% |
| Recall (matched / expected) | 100.0% |
| Matched alerts with the expected severity | 41 of 41 |
| Matched alerts with the expected evidence count | 41 of 41 |
| Negative and background cases that stayed silent | 14 of 15 |
| Documented blind spots that stayed silent, as documented | 5 of 5 |

Reconciliation (ok): expected 41 = matched 41 + missed 0; generated 43 = matched 41 + unexpected 2.

| Case | Kind | Scenario | Expected | Generated | Matched | Missed | Unexpected | Result |
|---|---|---|---|---|---|---|---|---|
| P01 | positive | Password spraying, window exactly 10:00 | 1 | 1 | 1 | 0 | 0 | pass |
| P02 | positive | One IP hammering one account | 2 | 2 | 2 | 0 | 0 | pass |
| P03 | positive | One account, five source IPs | 1 | 1 | 1 | 0 | 0 | pass |
| P04 | positive | High-volume spray escalates severity | 1 | 1 | 1 | 0 | 0 | pass |
| P05 | positive | Sustained attack is ONE alert per rule | 2 | 2 | 2 | 0 | 0 | pass |
| P06 | positive | Two bursts 36 minutes apart are two alerts | 4 | 4 | 4 | 0 | 0 | pass |
| P07 | positive | Failures from 3 IPs, success from a new IP | 2 | 2 | 2 | 0 | 0 | pass |
| P08 | positive | Large burst then success: critical | 2 | 2 | 2 | 0 | 0 | pass |
| P09 | positive | Four denials, window exactly 10:00 | 1 | 1 | 1 | 0 | 0 | pass |
| P10 | positive | Denied password changes count as denials | 1 | 1 | 1 | 0 | 0 | pass |
| P11 | positive | Twelve denials escalate LL-004 | 1 | 1 | 1 | 0 | 0 | pass |
| P12 | positive | Mixed time-zone offsets | 1 | 1 | 1 | 0 | 0 | pass |
| P13 | positive | Account name case and padding | 1 | 1 | 1 | 0 | 0 | pass |
| P14 | positive | One IPv6 host written two ways | 1 | 1 | 1 | 0 | 0 | pass |
| P15 | positive | IPv4 and IPv4-mapped IPv6 are one host | 1 | 1 | 1 | 0 | 0 | pass |
| P16 | positive | Six failures in the same second | 2 | 2 | 2 | 0 | 0 | pass |
| P17 | positive | Two successes after one burst: one LL-003 alert | 2 | 2 | 2 | 0 | 0 | pass |
| P18 | positive | Success in the middle of an ongoing attack | 2 | 2 | 2 | 0 | 0 | pass |
| P19 | positive | Timestamps without an offset are read as UTC | 1 | 1 | 1 | 0 | 0 | pass |
| P20 | positive | Fractional seconds | 1 | 1 | 1 | 0 | 0 | pass |
| P21 | positive | Scripted guessing logged at one-second resolution | 2 | 2 | 2 | 0 | 0 | pass |
| P22 | positive | Denied logins are LL-004, not LL-001/LL-002 | 1 | 1 | 1 | 0 | 0 | pass |
| P23 | positive | Burst across UTC midnight | 2 | 2 | 2 | 0 | 0 | pass |
| B01 | boundary | Success exactly 15:00 after the burst | 2 | 2 | 2 | 0 | 0 | pass |
| B02 | boundary | Success 15:01 after the burst | 1 | 1 | 1 | 0 | 0 | pass |
| B03 | boundary | Failure and success in the same second | 1 | 1 | 1 | 0 | 0 | pass |
| B04 | boundary | Success BEFORE the failures | 1 | 1 | 1 | 0 | 0 | pass |
| N01 | negative | Four failures from one IP | 0 | 0 | 0 | 0 | 0 | pass |
| N02 | negative | Five failures spanning 10:01 (one IP) | 0 | 0 | 0 | 0 | 0 | pass |
| N03 | negative | Five failures spanning 10:01 (one account) | 0 | 0 | 0 | 0 | 0 | pass |
| N04 | negative | Three denials; four denials spanning 10:01 | 0 | 0 | 0 | 0 | 0 | pass |
| N05 | negative | Success after only four failures | 0 | 0 | 0 | 0 | 0 | pass |
| N06 | negative | Morning rush: 30 accounts log in within 3 minutes | 0 | 0 | 0 | 0 | 0 | pass |
| N07 | negative | Nightly batch job: 60 successful accesses in 5 minutes | 0 | 0 | 0 | 0 | 0 | pass |
| N08 | negative | Shared NAT address, slow trickle of mistakes | 0 | 0 | 0 | 0 | 0 | pass |
| N09 | negative | Typo, typo, typo, success | 0 | 0 | 0 | 0 | 0 | pass |
| N10 | negative | Five failures, five IPs, five accounts | 0 | 0 | 0 | 0 | 0 | pass |
| N11 | negative | Six denials spread over three accounts | 0 | 0 | 0 | 0 | 0 | pass |
| N12 | negative | Logouts and successful password changes | 0 | 0 | 0 | 0 | 0 | pass |
| N13 | negative | Intermittent failures, 6 minutes apart | 0 | 0 | 0 | 0 | 0 | pass |
| N14 | negative | Replayed log lines (each failure shipped twice) | 0 | 2 | 0 | 0 | 2 | FAIL |
| K01 | limitation | Low and slow guessing | 0 | 0 | 0 | 0 | 0 | pass |
| K02 | limitation | Distributed spray: 40 IPs x 40 accounts | 0 | 0 | 0 | 0 | 0 | pass |
| K03 | limitation | One identity written three ways | 0 | 0 | 0 | 0 | 0 | pass |
| K04 | limitation | Password spray, then a success from the same IP | 1 | 1 | 1 | 0 | 0 | pass |

The blind spots in the K cases are not counted as expected alerts: the activity there is attack-like but documented as not detected, and the check is that it stays silent.

Deviations:

- N14 - unexpected alert: LL-001 on 198.51.100.87
- N14 - unexpected alert: LL-002 on awojcik

## Run: exact duplicate rows removed

1,875 rows read, 1,864 events analysed, 39 alerts generated.

| Measure | Result |
|---|---|
| Expected alerts | 41 |
| Total alerts generated | 39 |
| Correctly matched alerts | 39 |
| Missed expected alerts | 2 |
| Unexpected alerts | 0 |
| Precision (matched / generated) | 100.0% |
| Recall (matched / expected) | 95.1% |
| Matched alerts with the expected severity | 39 of 39 |
| Matched alerts with the expected evidence count | 39 of 39 |
| Negative and background cases that stayed silent | 15 of 15 |
| Documented blind spots that stayed silent, as documented | 5 of 5 |

Reconciliation (ok): expected 41 = matched 39 + missed 2; generated 39 = matched 39 + unexpected 0.

| Case | Kind | Scenario | Expected | Generated | Matched | Missed | Unexpected | Result |
|---|---|---|---|---|---|---|---|---|
| P01 | positive | Password spraying, window exactly 10:00 | 1 | 1 | 1 | 0 | 0 | pass |
| P02 | positive | One IP hammering one account | 2 | 2 | 2 | 0 | 0 | pass |
| P03 | positive | One account, five source IPs | 1 | 1 | 1 | 0 | 0 | pass |
| P04 | positive | High-volume spray escalates severity | 1 | 1 | 1 | 0 | 0 | pass |
| P05 | positive | Sustained attack is ONE alert per rule | 2 | 2 | 2 | 0 | 0 | pass |
| P06 | positive | Two bursts 36 minutes apart are two alerts | 4 | 4 | 4 | 0 | 0 | pass |
| P07 | positive | Failures from 3 IPs, success from a new IP | 2 | 2 | 2 | 0 | 0 | pass |
| P08 | positive | Large burst then success: critical | 2 | 2 | 2 | 0 | 0 | pass |
| P09 | positive | Four denials, window exactly 10:00 | 1 | 1 | 1 | 0 | 0 | pass |
| P10 | positive | Denied password changes count as denials | 1 | 1 | 1 | 0 | 0 | pass |
| P11 | positive | Twelve denials escalate LL-004 | 1 | 1 | 1 | 0 | 0 | pass |
| P12 | positive | Mixed time-zone offsets | 1 | 1 | 1 | 0 | 0 | pass |
| P13 | positive | Account name case and padding | 1 | 1 | 1 | 0 | 0 | pass |
| P14 | positive | One IPv6 host written two ways | 1 | 1 | 1 | 0 | 0 | pass |
| P15 | positive | IPv4 and IPv4-mapped IPv6 are one host | 1 | 1 | 1 | 0 | 0 | pass |
| P16 | positive | Six failures in the same second | 2 | 2 | 2 | 0 | 0 | pass |
| P17 | positive | Two successes after one burst: one LL-003 alert | 2 | 2 | 2 | 0 | 0 | pass |
| P18 | positive | Success in the middle of an ongoing attack | 2 | 2 | 2 | 0 | 0 | pass |
| P19 | positive | Timestamps without an offset are read as UTC | 1 | 1 | 1 | 0 | 0 | pass |
| P20 | positive | Fractional seconds | 1 | 1 | 1 | 0 | 0 | pass |
| P21 | positive | Scripted guessing logged at one-second resolution | 2 | 0 | 0 | 2 | 0 | FAIL |
| P22 | positive | Denied logins are LL-004, not LL-001/LL-002 | 1 | 1 | 1 | 0 | 0 | pass |
| P23 | positive | Burst across UTC midnight | 2 | 2 | 2 | 0 | 0 | pass |
| B01 | boundary | Success exactly 15:00 after the burst | 2 | 2 | 2 | 0 | 0 | pass |
| B02 | boundary | Success 15:01 after the burst | 1 | 1 | 1 | 0 | 0 | pass |
| B03 | boundary | Failure and success in the same second | 1 | 1 | 1 | 0 | 0 | pass |
| B04 | boundary | Success BEFORE the failures | 1 | 1 | 1 | 0 | 0 | pass |
| N01 | negative | Four failures from one IP | 0 | 0 | 0 | 0 | 0 | pass |
| N02 | negative | Five failures spanning 10:01 (one IP) | 0 | 0 | 0 | 0 | 0 | pass |
| N03 | negative | Five failures spanning 10:01 (one account) | 0 | 0 | 0 | 0 | 0 | pass |
| N04 | negative | Three denials; four denials spanning 10:01 | 0 | 0 | 0 | 0 | 0 | pass |
| N05 | negative | Success after only four failures | 0 | 0 | 0 | 0 | 0 | pass |
| N06 | negative | Morning rush: 30 accounts log in within 3 minutes | 0 | 0 | 0 | 0 | 0 | pass |
| N07 | negative | Nightly batch job: 60 successful accesses in 5 minutes | 0 | 0 | 0 | 0 | 0 | pass |
| N08 | negative | Shared NAT address, slow trickle of mistakes | 0 | 0 | 0 | 0 | 0 | pass |
| N09 | negative | Typo, typo, typo, success | 0 | 0 | 0 | 0 | 0 | pass |
| N10 | negative | Five failures, five IPs, five accounts | 0 | 0 | 0 | 0 | 0 | pass |
| N11 | negative | Six denials spread over three accounts | 0 | 0 | 0 | 0 | 0 | pass |
| N12 | negative | Logouts and successful password changes | 0 | 0 | 0 | 0 | 0 | pass |
| N13 | negative | Intermittent failures, 6 minutes apart | 0 | 0 | 0 | 0 | 0 | pass |
| N14 | negative | Replayed log lines (each failure shipped twice) | 0 | 0 | 0 | 0 | 0 | pass |
| K01 | limitation | Low and slow guessing | 0 | 0 | 0 | 0 | 0 | pass |
| K02 | limitation | Distributed spray: 40 IPs x 40 accounts | 0 | 0 | 0 | 0 | 0 | pass |
| K03 | limitation | One identity written three ways | 0 | 0 | 0 | 0 | 0 | pass |
| K04 | limitation | Password spray, then a success from the same IP | 1 | 1 | 1 | 0 | 0 | pass |

The blind spots in the K cases are not counted as expected alerts: the activity there is attack-like but documented as not detected, and the check is that it stays silent.

Deviations:

- P21 - missed: LL-001 on 198.51.100.49
- P21 - missed: LL-002 on chaldane

