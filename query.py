import sqlite3
import json

conn = sqlite3.connect('starter-kit/starter-kit-sentinalzero/mock_simulator/mock_arena.db')
c = conn.cursor()
c.execute("SELECT task_id, dataset FROM mock_tasks WHERE dataset='live' OR task_id LIKE 'MSG-HIDDEN%'")
print(c.fetchall())
