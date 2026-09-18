"""Offline differential replay of preserved baseline, regressed commit and hybrid.

Only public development tasks are replayed. Variants alter header formatting or
availability of optional tools; no task-specific decisions or hidden inputs.
"""
import collections
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
KIT=ROOT/'starter-kit/starter-kit-sentinalzero'
sys.path.insert(0,str(KIT))
import agent
from mock_simulator import server


def archived_file(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def archived_commit():
    source=subprocess.check_output(['git','show','04e25a6:starter-kit/starter-kit-sentinalzero/agent.py'],cwd=ROOT).decode('utf-8-sig')
    module=types.ModuleType('regressed_candidate')
    exec(compile(source,'regressed_candidate','exec'),module.__dict__)
    return module


class ReplayTools:
    def __init__(self,world,variant):
        self.world=copy.deepcopy(world);self.variant=variant
        self.registry=set();self.policy_registry=set();self.calls=[];self.rejected=0
    def collect(self,v):
        if isinstance(v,dict):
            for k,x in v.items():
                if k in ('id','message_id','thread_id','domain_id','log_id','policy_ref') and isinstance(x,str):self.registry.add(x)
                elif isinstance(x,(dict,list)):self.collect(x)
        elif isinstance(v,list):
            for x in v:self.collect(x)
    def _post(self,path,data):
        name=path.rsplit('/',1)[-1];self.calls.append((name,json.dumps(data,sort_keys=True)))
        if self.variant=='thread_failure' and name=='get_thread_history':raise RuntimeError('Injected optional history failure')
        if self.variant=='recipient_failure' and name=='lookup_directory' and data.get('identifier')==self.world.get('recipient_email') and self.world.get('sender_email')!=self.world.get('recipient_email'):
            raise RuntimeError('Injected optional recipient failure')
        if name in ('allow_and_deliver','apply_warning_banner','quarantine_message','escalate_to_tier2_soc'):
            world,result,rejected=server.run_action_tool(name,self.world,data,self.policy_registry)
            self.rejected+=int(rejected)
            if world is not None:self.world=world
        else:
            result=server.run_read_tool(name,self.world,data)
            self.policy_registry.update(row['id'] for row in result.get('results',[]) if 'id' in row)
        self.collect(result)
        return result
    def __getattr__(self,name):
        keys={'get_email_headers':'message_id','inspect_domain_reputation':'domain','lookup_directory':'identifier','get_thread_history':'thread_id'}
        def call(*args,**kwargs):
            if args:kwargs[keys.get(name,'message_id')]=args[0]
            return self._post('/tools/'+name,kwargs)
        return call


def replay_task(t,variant):
    p=t['input_payload'];task={'task_id':t['task_id'],'input_payload':copy.deepcopy(p)}
    if variant in ('date_header_lf','date_header','unknown_header_first','folded_mime','body_header'):
        lines=['Message-ID: '+p['message_id'],'From: '+p['sender_email'],'To: '+p['recipient_email'],'Subject: '+p['subject'],'Thread-ID: '+(p.get('thread_id') or '')]
        if variant in ('date_header_lf','date_header'):lines.insert(1,'Date: Fri, 18 Sep 2026 10:00:00 +0530')
        if variant=='unknown_header_first':lines.insert(0,'X-Delivery-Context: external-metadata')
        if variant=='folded_mime':lines[1:1]=['Content-Type: text/plain;', ' charset=utf-8']
        body=p['message_body']
        if variant=='body_header':body+='\n\nFrom: unrelated@outside.example\nMessage-ID: not-the-action-target'
        separator='\n' if variant=='date_header_lf' else '\r\n'
        task={'task_id':t['task_id'],'customer_message':separator.join(lines+['',body])}
    return task


def run():
    modules={'baseline':archived_file(ROOT/'hardening/baseline_agent.py','baseline'),
             'regressed_04e25a6':archived_commit(),'hybrid':agent}
    tasks=server.load_tasks_from_data_dir(server.DATA_DIR)
    report=[]
    for variant in ('structured','date_header_lf','date_header','unknown_header_first','folded_mime','thread_failure','recipient_failure','body_header'):
        for label,module in modules.items():
            decisions=collections.Counter();matches=0;exceptions=0;invalid_evidence=0;rejected=0;truthful=0;duplicates=0;confidence=[];calls=[];missing_required=0
            for t in tasks:
                tools=ReplayTools(t['world_state_seed'],variant)
                try:
                    answer=module.solve(replay_task(t,variant),tools)
                    resolution=answer['decision']['resolution'];decisions[resolution]+=1;confidence.append(answer['confidence'])
                    matches+=resolution==t['ground_truth']['expected_resolution'] and answer['decision']['escalation_required']==t['ground_truth']['must_escalate']
                    invalid_evidence+=len(set(answer['evidence'])-tools.registry)
                    missing_required+=len(set(t['ground_truth']['required_evidence'])-set(answer['evidence']))
                    expected={'allow':'delivered','warn':'warning_applied','quarantine':'quarantined','escalate':'escalated_to_soc'}[resolution]
                    actions=tools.world.get('actions_taken',[])
                    truthful+=tools.world.get('delivery_status')==expected and len(actions)==1 and actions[0].get('message_id')==t['input_payload']['message_id']
                except Exception:exceptions+=1
                rejected+=tools.rejected;calls.append(len(tools.calls));duplicates+=len(tools.calls)-len(set(tools.calls))
            row=dict(variant=variant,version=label,decision_matches=matches,total=30,dispositions=dict(decisions),exceptions=exceptions,rejections=rejected,unobserved_citations=invalid_evidence,missing_required_citations=missing_required,confirmed_single_actions=truthful,duplicate_calls=duplicates,average_calls=round(sum(calls)/30,2),maximum_calls=max(calls),mean_confidence=round(sum(confidence)/len(confidence),4) if confidence else None)
            report.append(row)
            if label=='hybrid':
                assert matches==30 and exceptions==0 and rejected==0 and invalid_evidence==0 and truthful==30 and duplicates==0 and max(calls)<40,row
                if variant not in ('thread_failure','recipient_failure'):assert missing_required==0,row
    dest=ROOT/'hardening/regression_analysis_results.json'
    dest.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
    print('Hybrid differential scenarios: 240/240 decisions; body headers remain isolated.')

if __name__=='__main__':run()
