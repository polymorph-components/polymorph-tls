# Test matrix

## Warnings

- target `composed-delegated-webcrypto`: no results (declared optional)

| Case | composed | composed-delegated | composed-delegated-webcrypto | jco-node | jco-node-delegated |
| --- | --- | --- | --- | --- | --- |
| data (1 cases) | pass | pass | — | pass | pass |
| delegated (3 cases) | 2 N/A, 1 pass | 1 N/A, 2 pass | — | 2 N/A, 1 pass | 1 N/A, 2 pass |
| handshake (1 cases) | pass | pass | — | pass | pass |
| identity (1 cases) | pass | pass | — | pass | pass |
| shutdown (1 cases) | pass | pass | — | pass | pass |

## Failures

None.

## Summary

- `composed`: 2 N/A, 5 pass (7 total)
- `composed-delegated`: 1 N/A, 6 pass (7 total)
- `composed-delegated-webcrypto`: no results
- `jco-node`: 2 N/A, 5 pass (7 total)
- `jco-node-delegated`: 1 N/A, 6 pass (7 total)
