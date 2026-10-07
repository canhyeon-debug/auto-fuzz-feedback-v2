# Trial Analysis / Feedback v2

이 문서는 실차 검증 피드백을 반영한 8개 우선 수정 사항과 실행 시 동작을 정리한다.

## 핵심 원칙

현재 Trial 도중 mutation을 바꾸지 않는다.

```text
Trial N 완료
→ 전체 로그 회수
→ Normal vs Mutation 분석
→ 이상반응 후보 저장
→ Trial N+1에서 동일 mutation 재현 확인
→ 재현된 후보만 이후 exploitation에 사용
```

## 반영한 8개 항목

1. **Normal을 주 비교군으로 사용**
   - Mutation 구간과 같은 길이의 Normal 구간 끝부분을 비교한다.
   - `Baseline → Normal`과 `Mutation → Recovery`는 진단용 지표로 남기며 feedback 점수에는 직접 사용하지 않는다.
   - Normal phase가 없는 과거 로그만 `Baseline vs Mutation` legacy fallback을 사용한다.

2. **재현 후 exploitation**
   - 최초 고득점 결과는 `CANDIDATE`이며 아직 interesting mutation이 아니다.
   - 다음 Trial은 자동으로 `VERIFY / EXACT_REPRODUCTION`이 되어 같은 payload를 다시 송신한다.
   - 기본적으로 후보 anomaly key 중 50% 이상이 다시 관찰되어야 `CONFIRMED`가 된다.
   - `CONFIRMED` 원본 mutation만 exploitation 후보에 들어간다.

3. **DBC-aware payload 분석**
   - 전체 raw payload가 새롭다는 이유만으로 anomaly를 만들지 않는다.
   - DBC가 있는 ID는 Normal에서 안정적인 DBC signal과 DBC 미정의 stable bit만 비교한다.
   - DBC가 없는 ID는 Normal에서 변하지 않았던 bit만 fallback으로 비교한다.

4. **CRC / counter / time 분리**
   - CRC, checksum, counter, alive counter, `*_BZ`, timestamp/time-like signal은 일반 payload anomaly에서 제외한다.
   - 어떤 field를 왜 제외했는지는 `metrics[].payload_analysis.ignored_dynamic_fields`에 기록한다.

5. **저주기 ID용 누적 정상 기준표**
   - 각 완료 Trial의 Baseline+Normal에서 관찰한 ID와 정상 관찰 시간을 `feedback_state.json.reference_catalog`에 누적한다.
   - 이전 정상 구간에서 본 ID는 Mutation 창에만 나타나도 `NEW_MESSAGE`로 판정하지 않는다.
   - 기본 정상 관찰 시간이 60초보다 짧으면 새로운 ID를 anomaly가 아닌 `INSUFFICIENT_EVIDENCE`로 보류한다.

6. **표본 부족 분리**
   - frame 수, 예상 frame 수 또는 timing interval 수가 부족하면 anomaly 점수를 만들지 않는다.
   - 결과는 `anomalies.json.insufficient_evidence`에 별도 저장되며 feedback 입력에서 제외된다.

7. **Pi 시계 보정 및 경계 guard**
   - receiver timestamp에 `source_offset - receiver_offset`을 적용해 B-CAN 송신 Pi 시간축에 맞춘다.
   - SSH 왕복시간의 절반을 각 측정의 불확실성으로 보고 phase 양쪽 경계를 제외한다.
   - offset, RTT 또는 상대 불확실성이 YAML 한계를 넘거나 guard가 phase 전체를 소모하면 중앙 실행은 캡처/송신 전에 중단한다.
   - raw JSONL timestamp는 수정하지 않고 분석 시에만 보정한다.

8. **CROSS_BUS 중복 제거**
   - `CROSS_BUS`를 별도 anomaly type으로 한 번 더 만들지 않는다.
   - 실제 `TIMING`, `PAYLOAD_CHANGE` 등의 anomaly에 `cross_bus: true/false` 속성만 붙인다.

## Feedback 상태

주요 상태는 다음과 같다.

```text
NOT_INTERESTING  관찰된 고득점 anomaly 없음
CANDIDATE        최초 관찰, 재현 대기
REPRODUCED       추가 재현 횟수가 더 필요함
CONFIRMED        재현 성공, exploitation 가능
REJECTED         재현 실패
```

기존 schema v1의 `interesting_mutations`는 신뢰하지 않고 로드 시
`legacy_unconfirmed_mutations`로 격리한다. 기존 raw 로그는 삭제하거나 덮어쓰지 않는다.

Payload anomaly의 재현 key에는 bus, CAN ID, anomaly type뿐 아니라 확인 가능한
DBC signal 이름 또는 undefined bit 집합도 포함한다. 따라서 같은 ID에서 전혀 다른
signal이 변한 결과는 기존 후보의 재현으로 인정하지 않는다.

## 설정

```yaml
time_sync:
  samples: 5
  warning_threshold_ms: 50
  boundary_guard_ms: 5
  max_absolute_offset_ms: 500
  max_round_trip_ms: 250
  max_relative_uncertainty_ms: 200

anomaly_thresholds:
  minimum_control_frames: 5
  minimum_mutation_frames: 3
  minimum_expected_frames: 3
  minimum_timing_intervals: 3
  new_message_minimum_frames: 3
  new_message_minimum_reference_seconds: 60
  payload_change_ratio: 0.20

feedback:
  interesting_score_threshold: 0.60
  confirmation:
    enabled: true
    minimum_overlap_ratio: 0.50
    required_reproductions: 1
```

## 실행 시 주의

여러 Trial을 한 번에 실행하면 candidate 다음 Trial이 자동 재현에 사용된다.

```bash
.venv/bin/python experiment_runner.py \
  --config experiment_runner.yaml \
  --experiment-id 2 \
  --target-id 0x366 \
  --source-bus B_CAN \
  --trials 10 \
  --random-seed 366 \
  --mutation-profile signal-aware \
  --execute
```

한 번에 `--trials 1`만 실행할 때는 다음 명령에서도 같은 `--experiment-id`를 사용해야
pending candidate가 이어지고 정확 재현 Trial이 생성된다. 새 experiment를 만들면 이전
experiment의 feedback은 의도적으로 이어받지 않는다.

## 저장 결과

- `anomalies.json`: schema v2 분석 결과, 모든 phase metric, 진단 비교, anomaly, 표본 부족, suppressed finding, clock alignment
- `feedback.json`: observation과 confirmation 상태, mutation-anomaly mapping
- `feedback_state.json`: candidate/confirmed/rejected 목록, pending confirmation, 누적 정상 ID catalog
- `metadata.json`: 적용한 threshold/feedback/time-sync policy와 raw clock sample, 정렬 결과

분산 Trial package는 생성 시점 DBC의 SHA-256도 같이 서명한다. 분석 PC의
DBC 내용이 달라진 경우 같은 결과 bundle을 다른 기준으로 재분석하지 않고 중단한다.
완료된 분산 Trial을 같은 bundle로 다시 분석하면 저장된 결과를 그대로 반환하며
feedback state를 두 번 갱신하지 않는다.

## 기존 실차 로그 읽기 전용 재검증

저장된 완료 Trial 10개(Trial 1, 3~11)를 raw 로그 수정 없이 같은 DBC로 다시 분석한 결과:

- 기존 anomaly: 1,703개
- v2 anomaly: 68개 (`PAYLOAD_CHANGE` 51, `TIMING` 16, `FREQUENCY_CHANGE` 1)
- `0x40` CRC/counter/time 계열 payload anomaly: 0개
- `0x17332811` false `NEW_MESSAGE`: 0개

남은 후보도 즉시 exploitation하지 않으며 다음 Trial exact reproduction을 통과해야 한다.

## 현재 한계

- 세 노트북 분산 모드는 각 노트북 시계가 NTP/chrony로 같은 UTC 기준에 동기화됐다는 가정이 필요하다. 한 Control PC가 세 Pi를 직접 SSH 제어하는 중앙 모드는 같은 PC 기준으로 offset을 측정하므로 이 문제가 없다.
- 과거 v1 로그를 자동으로 다시 써서 정상 ID catalog에 넣지는 않는다. v2로 완료한 Trial부터 catalog가 누적된다.
- 현재 판정은 설명 가능한 threshold 기반이다. 다중 비교 보정이나 차량 상태별 통계 모델은 후속 개선 대상이다.
