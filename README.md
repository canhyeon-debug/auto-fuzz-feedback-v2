# auto-fuzz-feedback-v2

Audi A5 `0x366 (Blinkmodi_02)` mutation과 Trial 단위 feedback 분석을 위한
Python/SocketCAN 실험 코드입니다.

핵심 흐름은 실시간 online feedback이 아니라 다음과 같은
previous-trial feedback 방식입니다.

```text
Trial N 실행 -> 전체 로그 회수 -> Normal vs Mutation 분석
-> anomaly 후보 생성 -> Trial N+1 exact reproduction
-> 재현된 후보만 exploitation에 사용
```

구현과 설정은 [`pi_can_lab/ANALYSIS_FEEDBACK_V2.md`](pi_can_lab/ANALYSIS_FEEDBACK_V2.md)를
먼저 참고하세요.

## 로컬 준비

이 공개 저장소에는 실차 raw CAN 로그, 실제 SSH 설정, 개인 키 및 Audi DBC를
포함하지 않습니다. 사용 권한이 있는 `A5.dbc`를 저장소 루트에 별도로 배치하고,
예제 설정을 복사해 각 환경의 값을 입력하세요.

```bash
cd pi_can_lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp experiment_runner.yaml.example experiment_runner.yaml
```

실차 송신은 안전 조건과 권한을 확인한 격리된 환경에서만 수행해야 하며,
`--execute`를 붙이지 않으면 preview로 동작합니다.

## 테스트

```bash
cd pi_can_lab
python -m unittest discover -v
```

DBC 의존 테스트에는 저장소 루트의 `A5.dbc`가 필요합니다.
