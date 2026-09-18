"""Network-free regression against unmodified official ASGI app and SDK."""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / 'starter-kit' / 'starter-kit-sentinalzero'
sys.path.insert(0, str(KIT))
import agent
from sdk.tools_client import ToolsClient
from mock_simulator import server


def run(module=agent, live=False):
    with tempfile.TemporaryDirectory() as temp:
        server.DB_PATH = str(Path(temp) / 'mock.db')
        with TestClient(server.app) as client:
            sdk = ToolsClient(client=client)
            counts, failures, confidence, evidence = [], [], [], []
            by_disposition = {}
            for i in range(30):
                task = client.post('/task/start').json()
                tid = task['task_id']
                sdk.set_active_task(tid)
                if live:
                    p = task['input_payload']
                    task = {'task_id':tid, 'customer_message': '\r\n'.join([
                        'Subject: '+p.get('subject',''), 'tO: '+p.get('recipient_email',''),
                        'Message-ID: '+p['message_id'], 'FROM: '+p.get('sender_email',''),
                        'Thread-ID: '+(p.get('thread_id') or ''), '', p.get('message_body','')])}
                answer = module.solve(task, sdk)
                result = sdk.submit_task(tid, payload=answer)
                if not result.get('correct'): failures.append({'task':tid,'result':result})
                confidence.append(answer['confidence']); evidence.append(len(answer['evidence']))
                by_disposition.setdefault(answer['decision']['resolution'], []).append(answer['confidence'])
                conn = server.get_db_connection()
                row = conn.execute('SELECT world_runtime_state FROM mock_task_assignments WHERE task_id=?', (tid,)).fetchone()
                # Column name is checked below against official database schema.
                state = json.loads(row[0])
                expected = {'allow':'delivered','warn':'warning_applied','quarantine':'quarantined','escalate':'escalated_to_soc'}[answer['decision']['resolution']]
                assert state['delivery_status'] == expected
                assert len(state['actions_taken']) == 1
                logs = conn.execute('SELECT tool_name,response_payload,was_enforcement_rejection FROM mock_tool_call_logs WHERE task_id=?',(tid,)).fetchall()
                assert not any(r[2] for r in logs)
                retrieved=set()
                def collect(v):
                    if isinstance(v,dict):
                        for k,x in v.items():
                            if k in ('id','message_id','thread_id','domain_id','log_id','policy_ref') and isinstance(x,str): retrieved.add(x)
                            elif isinstance(x,(list,dict)): collect(x)
                    elif isinstance(v,list):
                        for x in v:collect(x)
                for row in logs:collect(json.loads(row[1]))
                assert set(answer['evidence']) <= retrieved
                counts.append(len(logs)); conn.close()
            return dict(passed=30-len(failures),total=30,failures=failures,maximum_calls=max(counts),average_calls=round(sum(counts)/30,2),average_evidence=round(sum(evidence)/30,2),average_confidence=round(sum(confidence)/30,4),confidence_by_disposition={k: {'count':len(v),'mean':round(sum(v)/len(v),4)} for k,v in by_disposition.items()},rejections=0)

if __name__ == '__main__':
    if '--baseline' in sys.argv or '--pre-final' in sys.argv:
        filename = 'pre_final_agent.py' if '--pre-final' in sys.argv else 'baseline_agent.py'
        spec=importlib.util.spec_from_file_location('baseline',Path(__file__).with_name(filename))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    else: module=agent
    result=run(module,'--live-format' in sys.argv)
    print(json.dumps(result,indent=2))
    sys.exit(bool(result['failures']))
