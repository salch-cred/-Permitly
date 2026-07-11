import crypto from 'node:crypto';

export class JobQueue {
  constructor(database) { this.db=database; }
  enqueue(type,payload,{runAt=new Date().toISOString(),maxAttempts=8}={}){const id=`job_${crypto.randomUUID()}`;this.db.prepare('INSERT INTO jobs (id,type,payload,status,attempts,max_attempts,run_at,created_at) VALUES (?,?,?,\'pending\',0,?,?,?)').run(id,type,JSON.stringify(payload),maxAttempts,runAt,new Date().toISOString());return id;}
  claim(now=new Date().toISOString()){const job=this.db.prepare("SELECT * FROM jobs WHERE status='pending' AND run_at<=? ORDER BY run_at LIMIT 1").get(now);if(!job)return null;this.db.prepare("UPDATE jobs SET status='running', attempts=attempts+1, locked_at=? WHERE id=? AND status='pending'").run(now,job.id);return this.db.prepare('SELECT * FROM jobs WHERE id=?').get(job.id);}
  complete(id){this.db.prepare("UPDATE jobs SET status='complete', completed_at=? WHERE id=?").run(new Date().toISOString(),id);}
  fail(id,error){const job=this.db.prepare('SELECT * FROM jobs WHERE id=?').get(id);const terminal=job.attempts>=job.max_attempts;this.db.prepare('UPDATE jobs SET status=?, last_error=?, run_at=? WHERE id=?').run(terminal?'failed':'pending',String(error).slice(0,1000),new Date(Date.now()+Math.min(3600000,1000*2**job.attempts)).toISOString(),id);}
}
