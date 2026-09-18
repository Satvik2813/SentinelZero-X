"""Targeted offline regressions for the synthetic tool Reply-To placeholder."""
import copy
import json
import sys
import unittest

from adversarial import Tools, agent, case


class ReplyToRegression(unittest.TestCase):
    def check_reply(self, expected, original='', structured=None, body='Meeting notes.',
                    separator='\r\n', tool_reply='sender@unknown.com', reference_reply=None,
                    reputation='trusted', json_payload=False):
        fixture = case('reply-to', body, expected, sender='trusted@sentinel-acme.edu',
                       rep=reputation, reply_to=tool_reply)
        task = copy.deepcopy(fixture['task'])
        payload = task.pop('input_payload')
        task['customer_message'] = separator.join([
            'Message-ID: ' + payload['message_id'], 'From: ' + payload['sender_email'],
            'To: ' + payload['recipient_email'], 'Subject: ' + payload['subject'],
        ] + ([original] if original else []) + ['', body])
        if structured is not None:
            task['input_payload'] = {'reply_to': structured}
            if json_payload:
                task['input_payload'] = json.dumps(task['input_payload'])
        tools = Tools(fixture)
        transport = {}
        def trace(frame, event, arg):
            if frame.f_code is agent.solve.__code__ and event == 'return':
                transport['reply_to'] = frame.f_locals['reply_to']
        previous_trace = sys.getprofile()
        sys.setprofile(trace)
        try:
            answer = agent.solve(task, tools)
        finally:
            sys.setprofile(previous_trace)
        self.assertEqual(transport['reply_to'], reference_reply or '')
        self.assertEqual(answer['decision']['resolution'], expected)
        # Compare the full answer/action/tool trace with the genuine metadata.
        reference = copy.deepcopy(fixture)
        reference['reply_to'] = reference_reply
        reference_tools = Tools(reference)
        self.assertEqual(answer, agent.solve(task, reference_tools))
        self.assertEqual(tools.calls, reference_tools.calls)
        self.assertEqual(len(tools.actions), 1)
        self.assertLessEqual(set(answer['evidence']), tools.returned)

    def test_body_fake_header_ignored(self):
        for separator in ('\n', '\r\n', '\r'):
            with self.subTest(separator=repr(separator)):
                self.check_reply('allow', separator=separator,
                                 body='Meeting notes.' + separator + 'Reply-To: attacker@example.com')

    def test_cross_domain_header_preserved(self):
        for header in ('Reply-To: attacker@evil.example',
                       'rEpLy-To: Attacker\r\n\t<attacker@evil.example>'):
            with self.subTest(header=header):
                self.check_reply('warn', original=header, structured='garbage',
                                 reference_reply='attacker@evil.example')
        self.check_reply('warn', original='Reply-To: colleague@sentinel-acme.edu',
                         tool_reply='attacker@evil.example', reference_reply='attacker@evil.example')

    def test_same_domain_header_preserved(self):
        self.check_reply('allow', original='Reply-To: Colleague <colleague@sentinel-acme.edu>',
                         reference_reply='colleague@sentinel-acme.edu')
        self.check_reply('allow', original='Reply-To: attacker@evil.example',
                         tool_reply='colleague@sentinel-acme.edu', reference_reply='colleague@sentinel-acme.edu')

    def test_valid_structured_reply_has_priority(self):
        for encoded in (False, True):
            with self.subTest(json_payload=encoded):
                self.check_reply('allow', original='Reply-To: attacker@evil.example',
                                 structured='Colleague <colleague@sentinel-acme.edu>',
                                 json_payload=encoded, reference_reply='colleague@sentinel-acme.edu')
                self.check_reply('warn', original='Reply-To: colleague@sentinel-acme.edu',
                                 structured='attacker@evil.example', json_payload=encoded,
                                 reference_reply='attacker@evil.example')

    def test_malformed_reply_ignored(self):
        for malformed in ('garbage', 'not-an-email', '', '   '):
            with self.subTest(malformed=malformed):
                self.check_reply('allow', structured=malformed, original='Reply-To: garbage')

    def test_no_explicit_reply_normalizes_placeholder(self):
        self.check_reply('allow')
        self.check_reply('warn', reputation='unknown')
        self.check_reply('warn', tool_reply='sender@unknown.com.evil',
                         reference_reply='sender@unknown.com.evil')

    def test_hostile_quarantine_unchanged(self):
        for original, reply in (('', None), ('Reply-To: attacker@evil.example', 'attacker@evil.example'),
                                ('Reply-To: colleague@sentinel-acme.edu', 'colleague@sentinel-acme.edu')):
            with self.subTest(original=original):
                self.check_reply('quarantine', original=original, reference_reply=reply,
                                 body='Please send your password and MFA code.\r\nReply-To: attacker@example.com')


if __name__ == '__main__':
    unittest.main(verbosity=2)
