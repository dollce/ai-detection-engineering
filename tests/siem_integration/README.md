# Elasticsearch evidence validation

These opt-in tests execute stored compiled queries against temporary
`sim-validation-*` indices. Use a disposable Elasticsearch instance with the
repository's `sim-logs` mapping. No rules are deployed, and detection request
states are not changed. Each validator deletes its temporary index.

For an isolated Elasticsearch matching `docker-compose.yml`:

```bash
docker run --detach --rm --name issue-4-validation-es --memory=2g \
  --publish 127.0.0.1:19204:9200 \
  --env discovery.type=single-node --env xpack.security.enabled=false \
  --env xpack.ml.enabled=false --env 'ES_JAVA_OPTS=-Xms1g -Xmx1g' \
  docker.elastic.co/elasticsearch/elasticsearch:8.17.0
```

Wait until `curl -f http://127.0.0.1:19204/_cluster/health` succeeds. From the
repository root, apply exactly the `setup.sh` template and the existing cleanup
policy to this disposable cluster:

```bash
python3 - <<'PY'
import json
import sys
from pathlib import Path
sys.path.insert(0, 'autonomous')
from orchestration.validation import _es_request

source = Path('setup.sh').read_text()
anchor = source.index('"http://localhost:9200/_index_template/sim-logs"')
start = source.index("-d '", anchor) + 4
end = source.index("'", start)
template = json.loads(source[start:end])
policy = json.loads(Path('pipeline/validation-ilm-policy.json').read_text())
for endpoint, data in [('_index_template/sim-logs', template),
                       ('_ilm/policy/validation-cleanup', policy)]:
    print(_es_request(f'http://127.0.0.1:19204/{endpoint}', method='PUT',
                      data=data, auth=('elastic', 'changeme')))
PY

ES_VALIDATION_URL=http://127.0.0.1:19204 \
  python3 -m unittest discover -s tests/siem_integration -v

python3 autonomous/orchestration/revalidate_evidence.py \
  --es-url http://127.0.0.1:19204 \
  --technique T1016 --technique T1055_EQL \
  --technique T1059.001_T1547.001_EQL --technique T1087.002_EQL \
  --technique T1489

python3 autonomous/orchestration/validation_audit.py \
  --output-dir /tmp/validation-audit

docker stop issue-4-validation-es
```

The refresh command writes `tests/results/<technique>.json` only after complete
successful native validation. `--output-dir` selects another evidence directory.
`ES_USER`/`ES_PASS` override lab credentials. Failures return nonzero and preserve
prior result files. Stored evidence includes source hashes, full query, server
version, event counts, scoring units and validator details.

EQL and threshold metrics describe one attack scenario and one benign scenario,
queried separately. Sigma metrics count individual events. Temporal validators
preserve supplied timestamps and reject missing timestamps. Threshold validation
checks sliding windows over fixture time using the compiled artifact's `from`
duration; it does not emulate the production scheduler. T1489 currently has an
11-minute compiled lookback although its source description says 5 minutes.

For issue #4, the repaired T1016 scenario has TP=3, FP=0, FN=0, TN=2. Each of the
three EQL scenarios and T1489 has TP=1, FP=0, FN=0, TN=1 at scenario level. These
are synthetic scenario results on Elasticsearch 8.17.0 using the `setup.sh`
template, not production telemetry, Splunk, Cribl or scheduled-alert validation.
The simulator defines a separate template and may overwrite live mappings;
these results do not establish equivalence with a running simulator's mappings.
