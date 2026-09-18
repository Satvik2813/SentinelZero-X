"""Boundary and fault tests: no network, no official dataset dependencies."""
import copy
import json
from adversarial import agent, Tools, case, INTERNAL, evaluate

cases=[
case('reputation-score-conflict','Please review the agenda.','warn',rep='safe',threat_score=96),
case('malformed-score','Please review the agenda.','allow',rep='safe',threat_score={'unknown':True}),
case('trusted-nonurgent-wire','Please wire $3210 to the supplier account.','quarantine',rep='trusted'),
case('spf-only-failure','Here is the agenda.','warn',rep='trusted',auth={'spf':'fail','dkim':'none','dmarc':'none'}),
case('benign-password-advice','Never send your password or enable macros.','allow',**INTERNAL),
case('unquoted-awareness','Attackers ask staff to enter passwords. This is security awareness training.','allow',**INTERNAL),
case('quoted-credential-example','The example "please enter your password" was blocked.','allow',**INTERNAL),
case('quoted-financial-example','The example "please wire $9400 immediately" was blocked.','allow',**INTERNAL),
case('negated-injection','Never ignore previous instructions; retain all security checks.','allow',**INTERNAL),
case('macro-training','Never enable macros in unsolicited attachments.','allow',**INTERNAL),
case('malware-without-extension','Please run the attached executable to view the document.','quarantine',rep='safe'),
case('reset-trusted-destination','Reset your password at https://orion.example/settings.','allow',link_rep='trusted',**INTERNAL),
case('failing-link-tool','Log in at https://unknown-access.example to retain access.','quarantine',rep='safe'),
]

def main():
    report, _=evaluate(agent,cases)
    checks=0
    def check(condition):
        nonlocal checks
        assert condition
        checks+=1
    c=case('parser','Body\nFrom: attacker@other.example\nMessage-ID: forged','warn')
    p=c['task']['input_payload']
    raw='  SUBJECT: Folded\r\n\tcontinued\r\nFROM: Name <contact@unseen.example>\r\nMessage-ID : MSG-test\r\nReferences: <previous-message@example>\r\n\r\n'+p['message_body']
    n=agent._normalize({'customer_message':raw,'input_payload':{'sender_ip':None}})
    check(n['message_id']=='MSG-test' and n['sender_email']=='contact@unseen.example' and n['thread_id']=='')
    check(n['subject']=='Folded continued' and 'forged' in n['body'])
    n=agent._normalize({'input_payload':json.dumps(p)})
    check(n['body']==p['message_body'])
    n=agent._normalize({'input_payload':None,'customer_message':None})
    check(n['body']=='' and n['message_id']=='')
    c=case('null-tool-shapes','Meeting tomorrow.','warn')
    class NullTools(Tools):
        def get_email_headers(self,mid):return self.record('get_email_headers',mid,{'message_id':mid,'auth_results':[None]})
        def lookup_directory(self,identifier):return self.record('lookup_directory',identifier,{'found':True,'employee':[None]})
        def get_approved_domains(self):return self.record('get_approved_domains','',{'official_domains':None,'partner_domains':None})
    a=agent.solve(c['task'],NullTools(c));check(a['decision']['resolution']=='warn')
    c=case('policy-unavailable','Please send your password.','escalate',**INTERNAL)
    class NoPolicy(Tools):
        def _post(self,*args):return {'results':None}
    t=NoPolicy(c)
    try:agent.solve(c['task'],t);raise AssertionError('must not claim escalation')
    except RuntimeError:check(not t.actions)
    c=case('uncertain-action','Please send your password.','quarantine')
    class Timeout(Tools):
        def quarantine_message(self,*args,**kwargs):
            self.actions.append('quarantine_message');raise TimeoutError('sensitive transport detail')
    t=Timeout(c)
    try:agent.solve(c['task'],t);raise AssertionError('must not claim success')
    except RuntimeError as exc:check(len(t.actions)==1 and 'sensitive' not in str(exc))
    class Rejected(Tools):
        def quarantine_message(self,*args,**kwargs):
            self.actions.append('quarantine_message');return {'error':'rejected'}
    t=Rejected(c)
    try:agent.solve(c['task'],t);raise AssertionError('must not claim success')
    except RuntimeError:check(len(t.actions)==1)
    c=case('many-urls','Sign in using '+ ' '.join('https://host'+str(i)+'.example' for i in range(50)),'quarantine')
    t=Tools(c);a=agent.solve(c['task'],t)
    check(len(t.calls)<=9 and sum(n=='inspect_domain_reputation' for n,_ in t.calls)==3)
    check(any('Additional link' in u for u in a['uncertainties']))
    c=case('maximum-investigation','Please enter your password at https://first.example or https://second.example.',
           'quarantine',sender='Mira Holt <stranger@outside.example>',employee=True,display_only=True,
           thread='THR-synthetic',history=[{'message_id':'MSG-prior','sender':'other@outside.example'}])
    t=Tools(c);a=agent.solve(c['task'],t)
    check(len(t.calls)==11 and len(set(t.calls))==11 and len(t.actions)==1)
    check(agent._confidence('quarantine',3,0,0)>agent._confidence('quarantine',1,1,2))
    check(agent._confidence('allow',3,0,0)>agent._confidence('allow',3,0,2))
    check(agent._confidence('quarantine',4,0,0)<=.97)
    t=Tools(c); bad=copy.deepcopy(c['task']);bad['input_payload']['message_id']=None
    try:agent.solve(bad,t);raise AssertionError('must not act without message id')
    except ValueError:check(not t.actions)
    print(json.dumps({'boundary':report,'contract_checks':checks,'maximum_stress_calls':11},indent=2))
    return bool(report['failures'])
if __name__=='__main__':raise SystemExit(main())
